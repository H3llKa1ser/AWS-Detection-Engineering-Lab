#!/usr/bin/env python3
"""
Live tier 1: conformance. No stack is deployed; this checks the assumptions the
offline suites rest on against the real services, in minutes and for very
little money.

  CloudWatch, catalogue  Every built-in metric-filter pattern (CIS, flow logs,
                         DNS, DNS Firewall), rendered offline by
                         ci/render-catalogue, against hand-written sample events
                         using the real TestMetricFilter API.
  CloudWatch, Sigma      Every Sigma rule converted to a metric filter, on the
                         Sigma suite's hand-written and randomised events: the
                         real service must agree with the CloudWatch model the
                         offline tests use (case-flipped events included).
  Athena, IP SQL         The canonical IP key and CIDR range SQL on real Athena
                         (Trino) against Python's ipaddress, the claim the
                         DuckDB tests can only make by proxy.

    python3 tests/live/test_conformance.py --catalogue-plan catalogue-plan.json \\
        --workgroup <ci workgroup> --report conformance-report.md

Needs AWS credentials (logs:TestMetricFilter, Athena on the CI workgroup).
"""
import argparse
import ipaddress
import json
import random
import sys

import boto3
from botocore.config import Config

import live_common as lc

import catalogue_samples       # noqa: E402
import sigma_convert as sc     # noqa: E402
import test_ip_keys as tk      # noqa: E402
import test_sigma as ts        # noqa: E402

CFG = Config(retries={"mode": "standard", "max_attempts": 10})


def catalogue_patterns(plan_path):
    plan = json.load(open(plan_path))
    return {r["change"]["after"]["name"].split("-", 1)[1]: r["change"]["after"]["pattern"]
            for r in plan["resource_changes"] if r["type"] == "aws_cloudwatch_log_metric_filter"}


def check_catalogue(logs, plan_path):
    patterns = catalogue_patterns(plan_path)
    missing = set(patterns) ^ set(catalogue_samples.SAMPLES)
    assert not missing, f"detections without samples, or samples without detections: {sorted(missing)}"
    problems = {}
    for name, pattern in sorted(patterns.items()):
        bad = lc.compare_with_service(logs, pattern, catalogue_samples.SAMPLES[name])
        if bad:
            problems[name] = bad
    assert not problems, "CloudWatch disagrees with expected matches (PROBE notes name the assumption): " + json.dumps(problems)[:3000]
    return f"{len(patterns)} patterns, {sum(len(v) for v in catalogue_samples.SAMPLES.values())} sample events agree"


def sigma_cases(conv, rnd):
    """(message, model_expectation, note) for a converted rule."""
    tree = ts.cwl_parse(conv["cloudwatch"])
    hand = ts.LAB_EXPECTATIONS.get(conv["slug"]) or ts.FIXTURE_EXPECTATIONS.get(conv["slug"].removeprefix("sigma_"), [])
    events, _, _ = ts.case_events(hand)
    random_events, _ = ts.random_events(conv, 150, rnd)
    cases = []
    for i, ev in enumerate(events + random_events):
        ev = dict(ev, eventID=f"conformance-{i}")          # unique messages
        cases.append((json.dumps(ev, separators=(",", ":")), ts.cwl_eval(tree, ev), "model"))
    return cases


def check_sigma(logs):
    rnd = random.Random(20261008)
    convs = [c for c in ts.lab_rules().values() if "cloudwatch" in c]
    convs += [c for c in (ts.fixture(n) for n in ts.FIXTURE_RULES) if "cloudwatch" in c]
    problems, total = {}, 0
    for conv in convs:
        cases = sigma_cases(conv, rnd)
        total += len(cases)
        bad = lc.compare_with_service(logs, conv["cloudwatch"], cases)
        if bad:
            problems[conv["slug"]] = bad[:5]
    assert not problems, "real CloudWatch disagrees with the model: " + json.dumps(problems)[:3000]
    return f"{len(convs)} Sigma patterns, {total} events: service == model"


def check_athena_ip_sql(athena):
    rnd = random.Random(7)
    tk.RND.seed(7)
    texts = {"::", "::1", "1::", "fe80::", "2001:db8::1", "0.0.0.0", "255.255.255.255"}
    while len(texts) < 1200:
        a = tk.rand_v6()
        texts |= {tk.rand_v4(), a.compressed, a.exploded, a.compressed.upper()}
    bad = ["", "1.2.3", "256.1.1.1", "01.2.3.4", "1::2::3", "12345::", "::ffff:1.2.3.4", "fe80::1%eth0", "AWS Internal"]
    got = {r["v"]: r["k"] for r in athena.query(lc.ip_key_query(sorted(texts) + bad))}
    wrong = [t for t in texts if got.get(t) != tk.py_key(t)] + [b for b in bad if got.get(b) is not None]
    assert not wrong, f"Athena ip_key differs from Python for: {wrong[:8]}"

    nets = [ipaddress.ip_network(f"{tk.rand_v4()}/{rnd.randint(0, 32)}", strict=False) for _ in range(300)]
    nets += [ipaddress.ip_network(f"{tk.rand_v6()}/{rnd.randint(0, 128)}", strict=False) for _ in range(300)]
    cidrs = [str(n) for n in nets]
    got = {r["cidr_text"]: (r["lo"], r["hi"]) for r in athena.query(lc.ranges_query(cidrs))}
    wrong = [c for c, n in zip(cidrs, nets)
             if got.get(c) != (tk.py_key(str(n.network_address)), tk.py_key(str(n.broadcast_address)))]
    assert not wrong, f"Athena CIDR ranges differ from Python for: {wrong[:8]}"

    pairs = []
    for n in nets[:400]:
        for a in (n.network_address, n.broadcast_address,
                  n.network_address + rnd.randint(0, n.num_addresses - 1)):
            pairs.append((str(n), str(a)))
        pairs.append((str(n), tk.rand_v4() if n.version == 4 else str(tk.rand_v6())))
    rows = athena.query(lc.membership_query(pairs))
    wrong = [(r["cidr_text"], r["a"]) for r in rows
             if (r["hit"] == "true") != (ipaddress.ip_address(r["a"]) in ipaddress.ip_network(r["cidr_text"]))]
    assert not wrong and len(rows) == len(pairs), f"membership differs: {wrong[:8]} ({len(rows)}/{len(pairs)} rows)"
    return f"{len(texts) + len(bad)} keys, {len(cidrs)} ranges, {len(pairs)} memberships match Python"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--catalogue-plan", required=True, help="terraform show -json of ci/render-catalogue")
    ap.add_argument("--workgroup", required=True, help="Athena workgroup for CI conformance queries")
    ap.add_argument("--region", default=None)
    ap.add_argument("--report", default="conformance-report.md")
    args = ap.parse_args()

    session = boto3.Session(region_name=args.region)
    logs = session.client("logs", config=CFG)
    athena = lc.Athena(session.client("athena", config=CFG), args.workgroup)

    checks = lc.Checks("Live conformance")
    checks.run("CloudWatch: built-in catalogue patterns vs samples", lambda: check_catalogue(logs, args.catalogue_plan))
    checks.run("CloudWatch: Sigma patterns, service vs model", lambda: check_sigma(logs))
    checks.run("Athena: IP key and CIDR SQL vs Python ipaddress", lambda: check_athena_ip_sql(athena))
    checks.write(args.report)
    print(checks.markdown())
    sys.exit(0 if checks.ok else 1)


if __name__ == "__main__":
    main()
