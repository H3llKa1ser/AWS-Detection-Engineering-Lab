# Curated threat intelligence

Indicators the hunts join against flow logs, DNS and CloudTrail
(hunts 22-25). Every `*.csv` in `indicators/` is validated, merged and uploaded
by Terraform; a change triggers a one-off **retro-hunt** over the full lookback.

## Format

| Column | Required | Values |
|--------|----------|--------|
| `indicator` | yes | IPv4 address, IPv4 CIDR, or domain (no scheme, no trailing dot) |
| `type` | yes | `ipv4`, `cidr` or `domain` |
| `source` | yes | Where it came from (`internal-ir-2026-031`, `feodotracker`, ...) |
| `confidence` | yes | `low`, `medium` or `high` |
| `added` | yes | `YYYY-MM-DD` |
| `expires` | yes | `YYYY-MM-DD`; expired indicators stop matching |
| `description` | yes | Why this is bad, in one sentence |
| `reference` | no | Ticket, report or URL |

A `domain` indicator also matches its subdomains (`evil.com` matches
`a.b.evil.com`, never `notevil.com`). IPv6 is not supported yet.

## Rules (enforced by `tests/intel/test_indicators.py` and at plan time)

- **Everything expires.** Infrastructure is recycled; a C2 IP from March is a
  cloud customer's web server by June. Default to 30-90 days, longer only for
  indicators you have re-verified.
- **No internal or reserved ranges** (RFC 1918, loopback, link-local, CGNAT),
  no CIDR wider than /16, and no platform apex domains (`amazonaws.com`,
  `cloudfront.net`, `github.com`, ...): with subdomain matching, those would
  match half your traffic. Documentation ranges (TEST-NET) and `.invalid` are
  allowed for canaries.
- **One row per indicator.** Duplicates across files fail validation; pick the
  stronger source and say so in the description.
- **Review like code.** Each change is a pull request with the source and
  reasoning; the git history is the audit trail of what you believed and when.

## Importing a feed

`scripts/import_feodo.py` turns abuse.ch's Feodo Tracker botnet C2 blocklist
into `indicators/feodotracker.csv` with a short expiry. Review the diff before
committing: feeds contain cloud IPs that get reassigned, which is exactly why
imported rows expire fast. Respect each feed's terms of use.
