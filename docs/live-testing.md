# Live testing in a sandbox account

The offline suites prove the lab's logic against models: hunts in DuckDB,
CloudWatch patterns against a model of the documented semantics. Two live tiers
check those models against the real services and the deployed stack against
real activity. Both run in GitHub Actions (`.github/workflows/live.yml`), only
on demand and weekly, behind an approval-gated environment.

> **Status:** the live tiers are written and verified offline (see "What is
> verified without AWS" below) but have not yet been run against AWS by the
> author. Expect the first run to surface environment details; the report
> says exactly which check failed and why.

## The tiers

| Tier | Deploys? | Time | What it proves |
|------|----------|------|----------------|
| **Conformance** | no | minutes | Real CloudWatch `TestMetricFilter` agrees with expected matches for all 26 built-in patterns and with the CloudWatch model for every Sigma pattern (case-flipped events included); real Logs Insights agrees with the model for every Sigma query, and probe events settle how JSON booleans and nulls behave; real Athena computes the IP keys and CIDR ranges exactly as Python's `ipaddress` does |
| **End to end** | yes (unique prefix) | ~1-2 hours | Every saved query executes in real Athena; the retro-hunt fired by the indicator upload completes; a scheduled run succeeds with no FAILED hunts; safe triggers raise their alarms via SNS; hunts find the triggered activity once CloudTrail and Firehose deliver to S3; the Sigma hunts return exactly the reference result on synthetic CloudTrail files |

Both start only after the full offline suite passes.

### Triggers used by the end-to-end tier

All are safe, reversible and scoped to the run's prefix:

- a security group created and deleted in the lab VPC (`security_group_changes`);
- an IAM user `e2e-...-target` created, an access key minted and deleted for
  it, the user deleted (hunt 05's "credential created for another identity");
- an SSM `SendCommand` to a non-existent instance, rejected but recorded
  (`sigma_ssm_command_by_human` metric-filter alarm, its Logs Insights log
  alarm, and its Athena hunt);
- the traffic generator's DNS (DNS Firewall block, `.onion`, mining-pool and
  TXT alarms; the DNS lake; the intel canary in hunt 23);
- synthetic CloudTrail log files written to the run's own CloudTrail bucket for
  the Sigma replay. They are tagged (`userAgent: e2e-synthetic/<prefix>/<n>`)
  and destroyed with the stack.

### Not covered

GuardDuty, Security Hub and AWS Config are off in `ci/e2e.tfvars`: they are one
per account and region (a sandbox managed by an organization may already have
them, which would make the apply fail), and enabling or disabling them is slow.
Flow-log content is not asserted (the isolated lab VPC has almost no flows); the
flow table and flow hunts are covered by "every saved query executes" and by the
conformance tier's flow-pattern samples. DNS Firewall Advanced verdicts are
behavioural and not asserted.

## Safety design

- **No stored credentials.** Jobs get short-lived credentials through GitHub
  OIDC. The role's trust policy accepts only tokens for this repository's
  `sandbox` environment, so forks, other repositories and jobs outside the
  environment cannot assume it. Configure required reviewers on the environment
  to make every live run an explicit approval.
- **Guardrails on the role.** Broad permissions (the lab creates most resource
  types) are contained by explicit denies: no changes to the CI role or its
  trust, no tampering with the state bucket or deletion of state history, no
  requests outside the one sandbox region (global services excepted), no
  organization or account changes, and IAM users or access keys only for
  `e2e-*` names.
- **Isolation.** Each run uses its own name prefix
  (`e2e-<run id>-<attempt>`) and its own state key. One `aws-sandbox`
  concurrency group covers the e2e and janitor workflows, with
  `cancel-in-progress: false`: cancelling mid-apply or mid-destroy would orphan
  resources.
- **Always clean up.** The destroy step runs whatever happened before it (if
  init succeeded), retries once, and only then deletes the run's state. A failed
  destroy keeps the state, and the daily janitor (`live-janitor.yml`) destroys
  any stack whose state is older than 6 hours, then sweeps test activity outside
  Terraform (alert queues, target users).
- **Cost.** Job timeouts, a 1 GiB scan cap on the conformance workgroup,
  1-day retention in `ci/e2e.tfvars`, and a monthly budget alert from the
  bootstrap. A run's cost is dominated by a t3.micro for its duration, CloudTrail
  and Firehose delivery, DNS Firewall queries and small Athena scans. Each
  destroyed run also leaves a KMS key in its 7-day deletion window. Watch the
  budget alerts rather than trusting an estimate.

These properties are asserted by `tests/live/test_harness_offline.py`, so an
edit that removes one (destroy no longer `always()`, cancellable runs, a
`pull_request` trigger, ...) fails CI.

## Setup (once)

1. Use a **dedicated sandbox account**. Nothing else should live in it.
2. With administrator credentials for that account:

   ```bash
   terraform -chdir=ci/bootstrap init
   terraform -chdir=ci/bootstrap apply -var budget_email=you@example.com
   terraform -chdir=ci/bootstrap output github_variables
   ```

   Set `create_oidc_provider=false` if the account already has the GitHub OIDC
   provider. Keep the bootstrap's own state somewhere safe; it is deliberately
   not managed by CI.
3. In GitHub: create the environment `sandbox`, add required reviewers, and add
   the four printed values as environment variables (`AWS_SANDBOX_ROLE_ARN`,
   `AWS_SANDBOX_REGION`, `AWS_SANDBOX_STATE_BUCKET`, `AWS_SANDBOX_CI_WORKGROUP`).
4. Actions → **live** → Run workflow → tier `conformance` first.

## Reading results

Each job writes a report to its summary page and uploads it as an artifact
(Markdown and JSON). Every check runs even if an earlier one fails, so one run
gives the whole picture.

- **Conformance, catalogue:** some samples are marked `PROBE`. They encode
  assumptions the CloudWatch documentation does not settle: `!=` on a missing
  field, unquoted values containing dots (as in AWS's own CIS patterns), quoted
  numbers in space-delimited patterns. If one fails, the documentation-based
  model is wrong on that point: correct the model in `tests/sigma/test_sigma.py`,
  re-run the offline suites, and record the finding.
- **Conformance, Sigma:** a disagreement means the real service and the model
  differ on an emitted pattern. The converter was written not to depend on the
  undocumented `!=`-on-missing behaviour, so a failure here is a real finding.
- **End to end:** timeouts on delivery checks (hunts over S3) usually mean
  CloudTrail or Firehose was slower than the 45-minute allowance; alarm timeouts
  mean a detection path is broken. Saved-query failures show Athena's error for
  each query.

## What is verified without AWS

`tests/live/test_harness_offline.py` (in the offline CI suite):

- the conformance SQL builders reproduce Python's answers in DuckDB and fit
  Athena's 256 KiB query limit;
- the catalogue samples agree with the CloudWatch model for the 21 JSON
  patterns, and every one of the 26 built-in detections has a positive and a
  negative sample (patterns rendered by `ci/render-catalogue`, a Terraform plan
  that needs no AWS access);
- every AWS API call in the harness passes botocore's validation against the
  real API models (a planted parameter typo is caught);
- CloudTrail log-file building, SNS parsing and the janitor's selection logic;
- the workflow safety properties above.

Also checked by hand during development: the state backend configuration
(including `use_lockfile`) is accepted by Terraform 1.10.5 and fails only on
credentials when given fake ones; an invalid backend argument is rejected
before any network call.
