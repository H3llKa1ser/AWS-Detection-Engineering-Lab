# Terratest suite

Go tests ([Terratest](https://terratest.gruntwork.io/) v1) for the lab's modules,
through small fixtures in `fixtures/`. One switch per fixture, `offline`, lets the
same configuration be planned without AWS or applied for real.

| Tier | Tests | Needs | Runs in CI |
|------|-------|-------|------------|
| **Unit** | `TestUnitLogging`, `TestUnitDetections`, `TestUnitAlerting` | Go, Terraform; no AWS | every push (`tests.yml`, job `terratest-unit`) |
| **Integration** | `TestIntegrationLogging`, `TestIntegrationDetectionAlarmsFire`, `TestIntegrationSigmaLogAlarmFires` | the sandbox account | on demand and weekly (`live.yml`, job `terratest`) |

**Unit:** plan the fixture with faked credentials (no AWS calls) and assert on the
planned resources: the CloudTrail bucket is versioned, KMS-encrypted and private,
the trail is multi-region with log validation, the key rotates; every detection
(the 15 CIS ones and every Sigma metric filter) has a filter on the given log group
and an alarm with the semantics the runbook assumes; the alert rules match
GuardDuty at the configured severity and new active HIGH/CRITICAL Security Hub
findings. Eight planted mistakes in the modules are all caught.

**Integration:** apply the fixture with a run-unique prefix, assert against the real
resources with the AWS SDK, destroy:

- logging: versioning, TLS-only bucket policy and public-access block on the real
  bucket; the trail is logging; the log group uses the KMS key;
- detections: CloudTrail-shaped events written straight into the log group (no
  CloudTrail delay) drive a CIS alarm and a Sigma alarm to `ALARM`, while an
  unrelated alarm stays out of `ALARM`;
- Sigma log alarms: the saved query exists on the log group, and a matching event
  drives the Logs Insights log alarm to `ALARM` (an AWS-invoked command, which the
  rule excludes, is written alongside).

The Sigma log-alarm module has no unit test: the `hashicorp/awscc` provider
validates credentials with STS whenever it is configured and has no option to
skip that, so no configuration using it can be planned offline.

## Parallelism

Tests run with `t.Parallel()`, but `terraform init` is serialized
(`initSerially` in `helpers_test.go`): Terraform's plugin cache, which CI enables
with `TF_PLUGIN_CACHE_DIR`, is not safe for concurrent writers. The first init
fills the cache, later ones only read it; plans and applies stay parallel.

## Run

```bash
cd test
go test ./... -count=1 -v                                  # unit tier; integration tests skip
TERRATEST_LIVE=1 go test ./... -run '^TestIntegration' -count=1 -timeout 100m -v   # sandbox only
```

Integration tests only run with `TERRATEST_LIVE=1`, and only against the account
your credentials point at: use the sandbox. With `TERRATEST_STATE_BUCKET` set (CI
sets it), each fixture keeps its state at
`terratest/<fixture>/<prefix>/terraform.tfstate` and deletes it after a clean
destroy; the janitor (`live-janitor.yml`) destroys any fixture whose state
outlived its run. That matters because Go does not run deferred cleanup when
`go test -timeout` fires, which is also why CI keeps Go's timeout 20 minutes
below the job's.
