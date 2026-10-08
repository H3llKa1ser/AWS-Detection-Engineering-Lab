# Validating the pipeline

Detections you have not tested are detections you do not have. Three levels,
cheapest first.

## Level 1 — GuardDuty sample findings

Generates one sample of every GuardDuty finding type. Exercises the
GuardDuty → EventBridge → SNS path end to end without any real attacker activity.

```bash
./scripts/generate-findings.sh
```

Under the hood: `aws guardduty create-sample-findings --detector-id <id>
--finding-types <types>`.

## Level 2 — Trip CloudTrail metric filters by hand

Each action below should produce the named alarm within ~5 minutes. All are safe
and reversible.

| Action | Detection tripped |
|--------|-------------------|
| `aws ec2 create-security-group --group-name detlab-test --description test` | security_group_changes |
| `aws iam create-policy --policy-name detlab-test --policy-document '{"Version":"2012-10-17","Statement":[]}'` | iam_policy_changes |
| Sign in to the console as an IAM user with MFA disabled | console_signin_no_mfa |
| `aws s3api put-bucket-acl ...` on a test bucket | s3_policy_changes |

Remember to clean up the test resources afterwards.

## Level 3 — Adversary emulation (real findings)

Use [Stratus Red Team](https://github.com/DataDog/stratus-red-team) for genuine
TTPs that trigger *real* GuardDuty findings, not samples:

```bash
stratus list
stratus detonate aws.credential-access.ec2-get-password-data
stratus detonate aws.defense-evasion.cloudtrail-stop
stratus cleanup --all
```

`aws.defense-evasion.cloudtrail-stop` is a good end-to-end test: it should trip
both your `cloudtrail_config_changes` metric filter and a GuardDuty finding.
