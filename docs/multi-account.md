# Multi-account: GuardDuty and Security Hub for an organization

The lab's single-account stack turns GuardDuty and Security Hub on in one account.
In an AWS Organization the recommended pattern is a **delegated administrator**:
a dedicated security tooling account that enables and configures both services
for every account and region, and receives every finding.

```
 Management account            Delegated administrator            Member accounts
 (org/management)              (org/security-admin)               (lab root, optional)
 ─────────────────             ─────────────────────────          ─────────────────────
 GuardDuty trusted access ──►  GuardDuty, per region:              detectors enabled by
 GuardDuty admin, per region   detector, org config (ALL),          GuardDuty (auto-enable)
 Security Hub on (prereq)      protection plans
 Security Hub admin (home) ──► Security Hub central configuration:  Security Hub enabled
                               aggregator (home + linked regions),   by the policy
                               CENTRAL, policy, associations
                               Alerting: SNS for all findings
```

## What AWS requires (and how the code follows it)

| Requirement | Source | Where |
|-------------|--------|-------|
| GuardDuty needs Organizations trusted access before an API-designated admin (only its console enables it for you) | AWS Organizations user guide, GuardDuty | `terraform_data.guardduty_trusted_access` (one idempotent CLI call; `enable_guardduty_trusted_access = false` if your landing zone manages it) |
| GuardDuty admin designated in every region, the same account in all | GuardDuty user guide | `aws_guardduty_organization_admin_account` for each of `regions` |
| GuardDuty organization configuration per region, using the admin's detector | GuardDuty user guide | detector, organization configuration and features for each region |
| Security Hub enabled in the management account before delegating | AWS Security Blog (central configuration prerequisites) | `aws_securityhub_account.management` (no default standards) |
| Security Hub admin designated in the intended home region; trusted access enabled automatically | Security Hub and Organizations docs | `aws_securityhub_organization_admin_account` in `home_region` |
| Central configuration: admin is a member account, finding aggregator in the home region, `CENTRAL` with `auto_enable = false` and `auto_enable_standards = "NONE"`, policies managed from the home region | Security Hub user guide | `org-security-admin`; ordering enforced with `depends_on` |

AWS now calls the posture service **Security Hub CSPM**; the APIs and Terraform
resources keep the `securityhub` name.

All resources use the `hashicorp/aws` 6.x per-resource `region` argument, so one
configuration covers every region without a provider alias per region.

## Before you start

- An organization with all features enabled, and a member account for security
  tooling (Control Tower's Audit account is the usual choice).
- No existing GuardDuty or Security Hub delegated administrator, or the same
  account already delegated (import it; see below).
- Opt-in regions you list must be enabled in the delegated administrator account:
  if it opts out of a region, GuardDuty cannot enable members there.

## Apply

1. **Management account** (management credentials; the AWS CLI on PATH for the
   GuardDuty trusted-access call):

   ```bash
   cp org/management/terraform.tfvars.example org/management/terraform.tfvars   # edit
   terraform -chdir=org/management init && terraform -chdir=org/management apply
   ```

2. **Delegated administrator** (its credentials):

   ```bash
   cp org/security-admin/terraform.tfvars.example org/security-admin/terraform.tfvars   # edit
   terraform -chdir=org/security-admin init && terraform -chdir=org/security-admin apply
   ```

   `policy_targets` is the organization root (`r-...`) for everything, or OUs
   (`ou-...`) to roll out gradually. Each root has a `check` that warns at plan
   time if your credentials are for the wrong account.

3. **Member accounts running the lab:** set
   `organization_managed_threat_detection = true`. The lab then creates no
   detector or hub (they are the administrator's), but keeps its alert rules on
   the account's own findings.

4. **Verify** (delegated administrator credentials), now and again after a day:

   ```bash
   python3 scripts/verify_org.py --home-region eu-west-1 \
       --regions eu-west-1 eu-central-1 us-east-1 --targets r-abcd
   ```

   It checks, per region, the GuardDuty detector, auto-enable and that every
   member is `Enabled`; and in the home region that central configuration is
   `ENABLED`, the aggregator links exactly the other regions, and every policy
   association is `SUCCESS`. GuardDuty can take up to 24 hours to reach every
   member, so members still pending on the first run are expected.

## Defaults and costs

- **GuardDuty** auto-enables every member account (`ALL`), with S3 data events and
  EBS malware protection. Runtime, EKS, RDS and Lambda monitoring are off by
  default because they bill per resource in every account; turn them on in
  `guardduty_features`.
- **Security Hub** policy: service on, AWS Foundational Security Best Practices
  and CIS AWS Foundations 1.4.0, no controls disabled. Under central
  configuration, controls for global resources run only in the home region.
- **Alerts**: the administrator's alert topic receives GuardDuty findings at or
  above `min_guardduty_severity` and HIGH/CRITICAL Security Hub findings. Member
  GuardDuty findings arrive in the administrator account, and the aggregator
  brings every linked region's Security Hub findings (GuardDuty's included) into
  the home region, so one set of rules covers all accounts and regions.

## Existing setups

If a delegated administrator already exists, import instead of creating:

```bash
terraform -chdir=org/management import 'module.delegation.aws_guardduty_organization_admin_account.this["eu-west-1"]' <admin-account-id>
terraform -chdir=org/management import module.delegation.aws_securityhub_organization_admin_account.this <admin-account-id>
```

These examples are for the provider's default region (`home_region`). For
instances in other regions, the region has to be given with the import; see the
`hashicorp/aws` 6.x guide on enhanced region support for the form. Import an
existing detector or finding aggregator in `org/security-admin` the same way
(`terraform plan` lists what it would create).

## Tearing down

Both delegations carry `prevent_destroy`: removing the GuardDuty delegated
administrator detaches every member account, and changing Security Hub's stops
central configuration for the organization. A plan that would do either fails.
To tear down deliberately: destroy `org/security-admin`, remove the
`prevent_destroy` lines in `modules/org-delegation/main.tf`, then destroy
`org/management`.

## How this is tested

AWS Organizations cannot be exercised in the sandbox CI (it needs a real
organization, and the sandbox role is denied organization changes), so:

- `tests/org/test_org_plans.py` plans both roots offline (credentials faked with an
  override file) and asserts on the planned resources: every region delegated,
  detected and configured; protection plans per region; the aggregator linking
  exactly the non-home regions (and `NO_REGIONS` for one region); central
  configuration's required values; the ordering trusted access → delegation and
  aggregator → `CENTRAL` → policy; standards ARNs in the home region; associations;
  alert rules; invalid inputs refused; and an existing delegation not replaceable
  by accident. Seven planted mistakes in the modules are all caught.
- `tests/org/test_verify_org.py` checks every API call of `scripts/verify_org.py`
  against the AWS API models and that each problem is reported.

These roots have not been applied to a real organization by the author; run
`scripts/verify_org.py` after you apply.
