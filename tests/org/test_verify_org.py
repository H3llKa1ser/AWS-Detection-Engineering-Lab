#!/usr/bin/env python3
"""Offline tests for scripts/verify_org.py: every API call is validated against
the AWS API models (botocore Stubber), and each kind of problem is reported."""
import pathlib
import sys
import traceback

import boto3
from botocore.stub import Stubber

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_org as vo  # noqa: E402


def client(svc):
    return boto3.client(svc, region_name="eu-west-1", aws_access_key_id="x", aws_secret_access_key="x")


def gd_stub(st, auto="ALL", statuses=("Enabled", "Enabled")):
    st.add_response("list_detectors", {"DetectorIds": ["d1"]}, {})
    st.add_response("describe_organization_configuration", {"AutoEnableOrganizationMembers": auto,
                    "Features": [{"Name": "S3_DATA_EVENTS", "AutoEnable": "ALL"}], "MemberAccountLimitReached": False},
                    {"DetectorId": "d1"})
    members = [{"AccountId": f"33333333333{i}", "MasterId": "222222222222", "Email": "a@example.com",
                "RelationshipStatus": s, "UpdatedAt": "2026-10-08T00:00:00Z"} for i, s in enumerate(statuses)]
    st.add_response("list_members", {"Members": members}, {"DetectorId": "d1", "OnlyAssociated": "false"})


def sh_stub(st, ctype="CENTRAL", status="ENABLED", regions=("eu-central-1", "us-east-1"), assoc="SUCCESS"):
    arn = "arn:aws:securityhub:eu-west-1:222222222222:finding-aggregator/abc"
    st.add_response("describe_organization_configuration", {"AutoEnable": False, "AutoEnableStandards": "NONE",
                    "OrganizationConfiguration": {"ConfigurationType": ctype, "Status": status}}, {})
    st.add_response("list_finding_aggregators", {"FindingAggregators": [{"FindingAggregatorArn": arn}]}, {})
    st.add_response("get_finding_aggregator", {"FindingAggregatorArn": arn, "FindingAggregationRegion": "eu-west-1",
                    "RegionLinkingMode": "SPECIFIED_REGIONS", "Regions": list(regions)}, {"FindingAggregatorArn": arn})
    st.add_response("list_configuration_policy_associations", {"ConfigurationPolicyAssociationSummaries": [
        {"ConfigurationPolicyId": "p1", "TargetId": "r-ab12", "TargetType": "ROOT", "AssociationType": "APPLIED",
         "AssociationStatus": assoc}]}, {})


def test_healthy_organization_passes():
    gd, sh = client("guardduty"), client("securityhub")
    with Stubber(gd) as st:
        gd_stub(st)
        assert "2 members Enabled" in vo.guardduty_region(gd)
    with Stubber(sh) as st:
        sh_stub(st)
        assert "CENTRAL ENABLED" in vo.securityhub_home(sh, "eu-west-1", ["eu-west-1", "eu-central-1", "us-east-1"], ["r-ab12"])


def test_each_problem_is_reported():
    cases = [
        (lambda st: gd_stub(st, auto="NEW"), "guardduty", "auto-enable is NEW"),
        (lambda st: gd_stub(st, statuses=("Enabled", "Created")), "guardduty", "1 of 2 members not Enabled"),
        (lambda st: sh_stub(st, ctype="LOCAL"), "securityhub", "configuration type is LOCAL"),
        (lambda st: sh_stub(st, status="FAILED"), "securityhub", "central configuration FAILED"),
        (lambda st: sh_stub(st, regions=("eu-central-1",)), "securityhub", "aggregator links ['eu-central-1']"),
        (lambda st: sh_stub(st, assoc="FAILED"), "securityhub", "not SUCCESS ['r-ab12:FAILED']"),
    ]
    for stub, svc, needle in cases:
        c = client(svc)
        with Stubber(c) as st:
            stub(st)
            try:
                if svc == "guardduty":
                    vo.guardduty_region(c)
                else:
                    vo.securityhub_home(c, "eu-west-1", ["eu-west-1", "eu-central-1", "us-east-1"], ["r-ab12"])
                raise RuntimeError(f"expected a failure containing {needle!r}")
            except AssertionError as e:
                assert needle in str(e), (needle, str(e))


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {name}\n{traceback.format_exc()[-1500:]}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
