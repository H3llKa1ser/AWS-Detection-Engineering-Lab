#!/usr/bin/env python3
"""
Plan-based tests for the multi-account roots (org/management, org/security-admin).

AWS Organizations cannot be exercised in the sandbox CI (it needs a real
organization, and the sandbox role is denied organization changes), so these
tests plan each root OFFLINE, with an override file that fakes credentials, and
assert on what Terraform would create: every region delegated, detected and
configured; the aggregator linking exactly the non-home regions; central
configuration with its required settings and ordering; standards ARNs for the
home region; and invalid inputs refused at plan time.

    python3 tests/org/test_org_plans.py          (needs terraform on PATH)
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import traceback

ROOT = pathlib.Path(__file__).resolve().parents[2]
CACHE = pathlib.Path(tempfile.gettempdir()) / "tf-plugin-cache"
FAKE_PROVIDER = '''provider "aws" {
  region                      = var.home_region
  access_key                  = "plan-only"
  secret_key                  = "plan-only"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}
'''
MGMT, ADMIN = "111111111111", "222222222222"
REGIONS = ["eu-west-1", "eu-central-1", "us-east-1"]


def run(cmd, cwd):
    env = dict(os.environ, TF_PLUGIN_CACHE_DIR=str(CACHE), TF_IN_AUTOMATION="1")
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)


def plan(root, tfvars):
    """(plan JSON, None) on success, (None, error text) when Terraform refuses."""
    CACHE.mkdir(exist_ok=True)
    work = pathlib.Path(tempfile.mkdtemp())
    shutil.copytree(ROOT / "modules", work / "modules")
    shutil.copytree(ROOT / "org", work / "org")
    d = work / "org" / root
    (d / "provider_override.tf").write_text(FAKE_PROVIDER)
    (d / "test.tfvars.json").write_text(json.dumps(tfvars))
    init = run(["terraform", "init", "-input=false", "-backend=false"], d)
    assert init.returncode == 0, init.stderr
    p = run(["terraform", "plan", "-input=false", "-no-color", "-var-file=test.tfvars.json", "-out=plan.bin"], d)
    if p.returncode != 0:
        return None, p.stdout + p.stderr
    shown = run(["terraform", "show", "-json", "plan.bin"], d)
    return json.loads(shown.stdout), None


def resources(pj, rtype):
    return [r for r in pj["resource_changes"] if r["type"] == rtype and r["change"]["actions"] == ["create"]]


def module_config(pj, call):
    return pj["configuration"]["root_module"]["module_calls"][call]["module"]


def depends(pj, call, address):
    for r in module_config(pj, call)["resources"]:
        if r["address"] == address:
            return r.get("depends_on", [])
    raise KeyError(address)


# --- management ---------------------------------------------------------------------------

def mgmt_vars(**over):
    v = {"management_account_id": MGMT, "delegated_admin_account_id": ADMIN, "home_region": "eu-west-1",
         "regions": REGIONS}
    v.update(over)
    return v


def test_management_delegates_every_region_and_security_hub_in_home():
    pj, err = plan("management", mgmt_vars())
    assert err is None, err
    gd = resources(pj, "aws_guardduty_organization_admin_account")
    assert sorted(r["change"]["after"]["region"] for r in gd) == sorted(REGIONS), gd
    assert {r["change"]["after"]["admin_account_id"] for r in gd} == {ADMIN}
    [sh_acct] = resources(pj, "aws_securityhub_account")
    assert sh_acct["change"]["after"]["region"] == "eu-west-1" and sh_acct["change"]["after"]["enable_default_standards"] is False
    [sh_admin] = resources(pj, "aws_securityhub_organization_admin_account")
    assert sh_admin["change"]["after"] == {**sh_admin["change"]["after"], "region": "eu-west-1", "admin_account_id": ADMIN}
    assert "aws_securityhub_account.management" in depends(pj, "delegation", "aws_securityhub_organization_admin_account.this")
    assert len(resources(pj, "terraform_data")) == 1
    assert "terraform_data.guardduty_trusted_access" in depends(pj, "delegation", "aws_guardduty_organization_admin_account.this")


def test_existing_delegation_cannot_be_replaced_by_accident():
    """prevent_destroy: removing or changing the GuardDuty delegated administrator would
    detach every member account, so a plan that would do it must fail."""
    work = pathlib.Path(tempfile.mkdtemp())
    shutil.copytree(ROOT / "modules", work / "modules")
    shutil.copytree(ROOT / "org", work / "org")
    d = work / "org" / "management"
    (d / "provider_override.tf").write_text(FAKE_PROVIDER)
    (d / "test.tfvars.json").write_text(json.dumps(mgmt_vars(regions=["eu-west-1"], enable_guardduty_trusted_access=False)))
    assert run(["terraform", "init", "-input=false", "-backend=false"], d).returncode == 0
    state = {"version": 4, "terraform_version": "1.9.8", "serial": 1, "lineage": "test", "outputs": {}, "resources": [{
        "module": "module.delegation", "mode": "managed", "type": "aws_guardduty_organization_admin_account", "name": "this",
        "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
        "instances": [{"index_key": "eu-west-1", "schema_version": 0,
                       "attributes": {"id": "333333333333", "admin_account_id": "333333333333", "region": "eu-west-1"}}]}]}
    (d / "terraform.tfstate").write_text(json.dumps(state))
    p = run(["terraform", "plan", "-input=false", "-no-color", "-refresh=false", "-var-file=test.tfvars.json"], d)
    assert p.returncode != 0 and "prevent_destroy" in p.stdout + p.stderr, (p.stdout + p.stderr)[-600:]


def test_management_trusted_access_can_be_left_to_the_landing_zone():
    pj, err = plan("management", mgmt_vars(enable_guardduty_trusted_access=False))
    assert err is None, err
    assert resources(pj, "terraform_data") == []


def test_management_refuses_bad_input():
    cases = [(mgmt_vars(delegated_admin_account_id=MGMT), "Delegate to a member account"),
             (mgmt_vars(regions=["eu-central-1"]), "regions must include home_region"),
             (mgmt_vars(regions=["eu-west-1", "eu-west-1"]), "without duplicates"),
             (mgmt_vars(delegated_admin_account_id="12345"), "12-digit")]
    for tfvars, needle in cases:
        pj, err = plan("management", tfvars)
        assert pj is None and needle in err, (needle, (err or "")[-400:])


# --- security-admin ----------------------------------------------------------------------------

def admin_vars(**over):
    v = {"delegated_admin_account_id": ADMIN, "home_region": "eu-west-1", "regions": REGIONS,
         "policy_targets": ["r-ab12", "ou-ab12-cd34ef56"]}
    v.update(over)
    return v


def test_security_admin_configures_guardduty_in_every_region():
    pj, err = plan("security-admin", admin_vars())
    assert err is None, err
    assert sorted(r["change"]["after"]["region"] for r in resources(pj, "aws_guardduty_detector")) == sorted(REGIONS)
    orgcfg = resources(pj, "aws_guardduty_organization_configuration")
    assert sorted(r["change"]["after"]["region"] for r in orgcfg) == sorted(REGIONS)
    assert {r["change"]["after"]["auto_enable_organization_members"] for r in orgcfg} == {"ALL"}
    feats = resources(pj, "aws_guardduty_organization_configuration_feature")
    assert len(feats) == len(REGIONS) * 6, len(feats)
    by = {(r["change"]["after"]["region"], r["change"]["after"]["name"]): r["change"]["after"]["auto_enable"] for r in feats}
    assert all(by[(r, "S3_DATA_EVENTS")] == "ALL" and by[(r, "RUNTIME_MONITORING")] == "NONE" for r in REGIONS), by
    admin_feats = resources(pj, "aws_guardduty_detector_feature")
    assert sorted((r["change"]["after"]["region"], r["change"]["after"]["name"]) for r in admin_feats) == sorted(
        (r, f) for r in REGIONS for f in ("S3_DATA_EVENTS", "EBS_MALWARE_PROTECTION"))


def test_security_admin_central_configuration():
    pj, err = plan("security-admin", admin_vars())
    assert err is None, err
    [agg] = resources(pj, "aws_securityhub_finding_aggregator")
    a = agg["change"]["after"]
    assert a["region"] == "eu-west-1" and a["linking_mode"] == "SPECIFIED_REGIONS"
    assert sorted(a["specified_regions"]) == ["eu-central-1", "us-east-1"], a     # home region not linked to itself
    [org] = resources(pj, "aws_securityhub_organization_configuration")
    o = org["change"]["after"]
    assert (o["region"], o["auto_enable"], o["auto_enable_standards"]) == ("eu-west-1", False, "NONE")
    assert o["organization_configuration"][0]["configuration_type"] == "CENTRAL"
    assert "aws_securityhub_finding_aggregator.home" in depends(pj, "security_admin", "aws_securityhub_organization_configuration.central")
    [pol] = resources(pj, "aws_securityhub_configuration_policy")
    cp = pol["change"]["after"]["configuration_policy"][0]
    assert cp["service_enabled"] is True and sorted(cp["enabled_standard_arns"]) == sorted([
        "arn:aws:securityhub:eu-west-1::standards/aws-foundational-security-best-practices/v/1.0.0",
        "arn:aws:securityhub:eu-west-1::standards/cis-aws-foundations-benchmark/v/1.4.0"])
    assert "aws_securityhub_organization_configuration.central" in depends(pj, "security_admin", "aws_securityhub_configuration_policy.org")
    assocs = resources(pj, "aws_securityhub_configuration_policy_association")
    assert sorted(r["change"]["after"]["target_id"] for r in assocs) == ["ou-ab12-cd34ef56", "r-ab12"]
    assert {r["change"]["after"]["region"] for r in assocs} == {"eu-west-1"}
    rules = {r["change"]["after"]["name"] for r in resources(pj, "aws_cloudwatch_event_rule")}
    assert rules == {"org-security-guardduty-findings", "org-security-securityhub-findings"}, rules


def test_single_region_organization_links_no_regions():
    pj, err = plan("security-admin", admin_vars(regions=["eu-west-1"]))
    assert err is None, err
    [agg] = resources(pj, "aws_securityhub_finding_aggregator")
    assert agg["change"]["after"]["linking_mode"] == "NO_REGIONS" and agg["change"]["after"]["specified_regions"] is None


def test_security_admin_refuses_bad_input():
    cases = [(admin_vars(guardduty_features={"MAGIC_PROTECTION": "ALL"}), "Unknown GuardDuty feature"),
             (admin_vars(guardduty_features={"S3_DATA_EVENTS": "SOME"}), "ALL, NEW or NONE"),
             (admin_vars(auto_enable_members="EVERYONE"), "ALL, NEW or NONE"),
             (admin_vars(policy_targets=[]), "non-empty"),
             (admin_vars(policy_targets=["root"]), "r-..., ou-..."),
             (admin_vars(securityhub_standards=["cis 1.4"]), "<name>/v/<version>")]
    for tfvars, needle in cases:
        pj, err = plan("security-admin", tfvars)
        assert pj is None and needle in err, (needle, (err or "")[-400:])


def test_lab_root_steps_aside_in_an_organization():
    src = (ROOT / "main.tf").read_text()
    assert "enable_guardduty   = var.enable_guardduty && !var.organization_managed_threat_detection" in src
    assert "enable_securityhub = var.enable_securityhub && !var.organization_managed_threat_detection" in src


if __name__ == "__main__":
    if not shutil.which("terraform"):
        print("SKIP: terraform not on PATH")
        sys.exit(0)
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {name}\n{traceback.format_exc()[-1800:]}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
