#!/usr/bin/env python3
"""
Verify the multi-account setup after applying org/management and
org/security-admin. Run with DELEGATED ADMINISTRATOR credentials:

    python3 scripts/verify_org.py --home-region eu-west-1 \\
        --regions eu-west-1 eu-central-1 us-east-1 --targets r-abcd

GuardDuty, per region: a detector, organization auto-enable as expected, and
every member account's relationship "Enabled" (AWS notes the organization
configuration can take up to 24 hours to reach every account).
Security Hub, home region: central configuration ENABLED, the finding
aggregator linking exactly the other regions, and every policy association
SUCCESS.
"""
import argparse
import pathlib
import sys

import boto3

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tests" / "live"))
import live_common as lc  # noqa: E402  (Checks: run every check, report all)


def _paged(call, key, **kw):
    items, token = [], None
    while True:
        resp = call(**kw, **({"NextToken": token} if token else {}))
        items += resp.get(key, [])
        token = resp.get("NextToken")
        if not token:
            return items


def guardduty_region(gd, expect_auto="ALL"):
    detectors = gd.list_detectors().get("DetectorIds", [])
    assert detectors, "no GuardDuty detector in the delegated administrator account"
    det = detectors[0]
    cfg = gd.describe_organization_configuration(DetectorId=det)
    auto = cfg.get("AutoEnableOrganizationMembers")
    assert auto == expect_auto, f"organization auto-enable is {auto}, expected {expect_auto}"
    members = _paged(gd.list_members, "Members", DetectorId=det, OnlyAssociated="false")
    not_enabled = sorted(f"{m['AccountId']}:{m.get('RelationshipStatus')}" for m in members
                         if m.get("RelationshipStatus") != "Enabled")
    assert not not_enabled, (f"{len(not_enabled)} of {len(members)} members not Enabled "
                             f"(allow up to 24h after applying): {not_enabled[:10]}")
    plans = {f["Name"]: f["AutoEnable"] for f in cfg.get("Features", [])}
    return f"{len(members)} members Enabled; auto-enable {auto}; plans {plans}"


def securityhub_home(sh, home_region, regions, targets):
    org = sh.describe_organization_configuration()["OrganizationConfiguration"]
    assert org.get("ConfigurationType") == "CENTRAL", f"configuration type is {org.get('ConfigurationType')}"
    assert org.get("Status") == "ENABLED", f"central configuration {org.get('Status')}: {org.get('StatusMessage', '')}"
    aggs = _paged(sh.list_finding_aggregators, "FindingAggregators")
    assert len(aggs) == 1, f"expected one finding aggregator, found {len(aggs)}"
    agg = sh.get_finding_aggregator(FindingAggregatorArn=aggs[0]["FindingAggregatorArn"])
    assert agg["FindingAggregationRegion"] == home_region, f"aggregator in {agg['FindingAggregationRegion']}"
    linked = sorted(r for r in regions if r != home_region)
    got = sorted(r for r in agg.get("Regions", []) if r != home_region)
    assert got == linked, f"aggregator links {got}, expected {linked}"
    assocs = _paged(sh.list_configuration_policy_associations, "ConfigurationPolicyAssociationSummaries")
    by_target = {a["TargetId"]: a for a in assocs}
    missing = sorted(set(targets) - set(by_target))
    bad = sorted(f"{t}:{by_target[t]['AssociationStatus']}" for t in targets
                 if t in by_target and by_target[t].get("AssociationStatus") != "SUCCESS")
    assert not missing and not bad, f"policy associations missing {missing}, not SUCCESS {bad}"
    return f"CENTRAL ENABLED; aggregator links {linked or 'no other regions'}; {len(targets)} association(s) SUCCESS"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--home-region", required=True)
    ap.add_argument("--regions", nargs="+", required=True)
    ap.add_argument("--targets", nargs="+", required=True, help="policy targets (r-..., ou-..., account IDs)")
    ap.add_argument("--auto-enable", default="ALL")
    ap.add_argument("--report", default="org-verify-report.md")
    args = ap.parse_args(argv)
    checks = lc.Checks("Organization security verification")
    for region in args.regions:
        gd = boto3.client("guardduty", region_name=region)
        checks.run(f"GuardDuty {region}", lambda gd=gd: guardduty_region(gd, args.auto_enable))
    sh = boto3.client("securityhub", region_name=args.home_region)
    checks.run(f"Security Hub central configuration ({args.home_region})",
               lambda: securityhub_home(sh, args.home_region, args.regions, args.targets))
    checks.write(args.report)
    print(checks.markdown())
    return 0 if checks.ok else 1


if __name__ == "__main__":
    sys.exit(main())
