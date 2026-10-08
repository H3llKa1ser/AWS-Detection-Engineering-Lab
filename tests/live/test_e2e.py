#!/usr/bin/env python3
"""
Live tier 2: end to end, against a stack applied with ci/e2e.tfvars and a
unique name prefix. Creates only short-lived, reversible test activity and
cleans up what it creates; the workflow destroys the stack afterwards.

  plumbing  every saved query executes in real Athena; the retro-hunt fired
            by the apply-time indicator upload completed; a manual scheduled
            run succeeds; no "hunt FAILED" alert arrives
  alarms    a security group created and deleted, a failed SSM SendCommand,
            and the traffic generator's DNS each raise their alarm via SNS
  hunts     after CloudTrail/Firehose deliver to S3: hunt 05 finds an access
            key created for another user, the Sigma SSM hunt finds the
            command, the DNS lake has rows, hunt 23 finds the intel canary
  sigma     the Sigma suite's synthetic events, written as CloudTrail log
            files, give exactly the reference result in every Sigma hunt

    python3 tests/live/test_e2e.py --outputs outputs.json --prefix e2e-123-1 --report e2e-report.md
"""
import argparse
import json
import random
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

import live_common as lc

import test_sigma as ts   # noqa: E402

CFG = Config(retries={"mode": "standard", "max_attempts": 10})
ALARM_TIMEOUT = 35 * 60
DELIVERY_TIMEOUT = 45 * 60
EXPECTED_ALARMS = ["security_group_changes", "sigma_ssm_command_by_human", "dns_firewall_block",
                   "dns_onion_lookup", "dns_mining_pool_lookup", "dns_txt_query_spike"]


class Alerts(threading.Thread):
    """Collects SNS notifications from an SQS queue subscribed to the alert topic."""

    def __init__(self, session, topic_arn, prefix):
        super().__init__(daemon=True)
        self.sqs, self.sns = session.client("sqs", config=CFG), session.client("sns", config=CFG)
        self.messages, self.lock, self.stop = [], threading.Lock(), threading.Event()
        self.queue_url = self.sqs.create_queue(QueueName=f"{prefix}-e2e-alerts",
                                               tags={"Project": prefix, "Purpose": "e2e"})["QueueUrl"]
        qarn = self.sqs.get_queue_attributes(QueueUrl=self.queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        policy = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage",
            "Resource": qarn, "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}]}
        self.sqs.set_queue_attributes(QueueUrl=self.queue_url, Attributes={"Policy": json.dumps(policy)})
        self.sub_arn = self.sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=qarn,
                                          ReturnSubscriptionArn=True)["SubscriptionArn"]

    def run(self):
        while not self.stop.is_set():
            resp = self.sqs.receive_message(QueueUrl=self.queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
            for m in resp.get("Messages", []):
                with self.lock:
                    self.messages.append(lc.parse_sns_envelope(m["Body"]))
                self.sqs.delete_message(QueueUrl=self.queue_url, ReceiptHandle=m["ReceiptHandle"])

    def snapshot(self):
        with self.lock:
            return list(self.messages)

    def close(self):
        self.stop.set()
        self.join(timeout=30)
        try:
            self.sns.unsubscribe(SubscriptionArn=self.sub_arn)
        finally:
            self.sqs.delete_queue(QueueUrl=self.queue_url)


# --- Triggers and orchestration (module level so they can be stub-tested offline) ------------

def trigger_security_group(ec2, prefix, vpc_id):
    sg = ec2.create_security_group(GroupName=f"{prefix}-e2e-sg", Description="e2e trigger", VpcId=vpc_id)["GroupId"]
    ec2.delete_security_group(GroupId=sg)
    return sg


def trigger_access_key_for_other_user(iam, user):
    """Create a user, mint and delete an access key for it. The caller deletes the user."""
    iam.create_user(UserName=user, Tags=[{"Key": "Purpose", "Value": "e2e"}])
    key = iam.create_access_key(UserName=user)["AccessKey"]["AccessKeyId"]
    iam.delete_access_key(UserName=user, AccessKeyId=key)
    return key


def trigger_ssm_command(ssm):
    """A SendCommand to an instance that does not exist: rejected, but recorded by CloudTrail."""
    try:
        ssm.send_command(DocumentName="AWS-RunShellScript", InstanceIds=["i-0e2e0000000000000"],
                         Parameters={"commands": ["true"]})
    except ClientError as e:
        return f"recorded as {e.response['Error']['Code']} (expected: no such instance)"
    return "sent"


def find_retro_execution(sfn, machine):
    for page in sfn.get_paginator("list_executions").paginate(stateMachineArn=machine):
        for ex in page["executions"]:
            if '"retro/' in sfn.describe_execution(executionArn=ex["executionArn"]).get("input", ""):
                return ex["executionArn"]
    return None


def start_scheduled_run(sfn, scheduler, machine, prefix, now=None):
    schedule = scheduler.get_schedule(Name=f"{prefix}-daily-hunts")
    arn = sfn.start_execution(stateMachineArn=machine, name=f"e2e-manual-{int(now or time.time())}",
                              input=schedule["Target"]["Input"])["executionArn"]
    return arn, len(json.loads(schedule["Target"]["Input"])["hunts"])


def out(outputs, name):
    value = outputs[name]["value"]
    if value is None:
        raise KeyError(f"terraform output {name} is null; is the feature enabled in ci/e2e.tfvars?")
    return value


def execution_done(sfn, arn):
    d = sfn.describe_execution(executionArn=arn)
    return d if d["status"] != "RUNNING" else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outputs", required=True)
    ap.add_argument("--prefix", required=True)
    ap.add_argument("--region", default=None)
    ap.add_argument("--report", default="e2e-report.md")
    args = ap.parse_args()

    o = json.load(open(args.outputs))
    session = boto3.Session(region_name=args.region)
    region = session.region_name
    account = session.client("sts").get_caller_identity()["Account"]
    athena_client = session.client("athena", config=CFG)
    workgroup = out(o, "hunting_workgroup")
    database, table = out(o, "hunting_table").split(".")
    athena = lc.Athena(athena_client, workgroup, database)
    sfn = session.client("stepfunctions", config=CFG)
    machine = out(o, "scheduled_hunts_state_machine_arn")
    p = args.prefix
    checks = lc.Checks(f"Live end-to-end ({p})")
    cleanup = []

    alerts = Alerts(session, out(o, "alert_topic_arn"), p)
    alerts.start()
    cleanup.append(alerts.close)
    queries = lc.saved_queries(athena_client, workgroup)

    def named(prefix):
        hits = [sql for name, sql in queries.items() if name.startswith(prefix)]
        assert len(hits) == 1, f"expected one saved query starting {prefix!r}, found {len(hits)}"
        return hits[0]

    # --- plumbing ---------------------------------------------------------------------
    def all_saved_queries_execute():
        assert len(queries) >= 40, f"only {len(queries)} saved queries in {workgroup}"
        errors = {n: e for n, e in athena.run_all(queries).items() if e}
        assert not errors, json.dumps(errors)[:3000]
        return f"{len(queries)} saved queries executed"

    def retro_hunt_completed():
        arn = lc.wait_until(lambda: find_retro_execution(sfn, machine), 15 * 60, 30,
                            "the retro-hunt started by the indicator upload")
        d = lc.wait_until(lambda: execution_done(sfn, arn), 20 * 60, 20, "retro-hunt execution")
        assert d["status"] == "SUCCEEDED", d["status"]
        return arn.rsplit(":", 1)[-1]

    def scheduled_run_succeeds():
        arn, n = start_scheduled_run(sfn, session.client("scheduler", config=CFG), machine, p)
        d = lc.wait_until(lambda: execution_done(sfn, arn), 25 * 60, 20, "scheduled-hunts execution")
        assert d["status"] == "SUCCEEDED", d["status"]
        return f"{n} hunts ran"

    checks.run("every saved query executes in Athena", all_saved_queries_execute)
    checks.run("retro-hunt fired by the indicator upload completed", retro_hunt_completed)
    checks.run("scheduled-hunts run succeeds", scheduled_run_succeeds)

    # --- triggers (safe, reversible) ---------------------------------------------------------
    ec2, iam, ssm = (session.client(s, config=CFG) for s in ("ec2", "iam", "ssm"))
    target_user = f"{p}-target"

    cleanup.append(lambda: iam.delete_user(UserName=target_user))
    checks.run("trigger: security group created and deleted",
               lambda: trigger_security_group(ec2, p, out(o, "monitored_vpcs")["lab"]))
    checks.run("trigger: access key created for another user",
               lambda: trigger_access_key_for_other_user(iam, target_user) and target_user)
    checks.run("trigger: SSM SendCommand by a person", lambda: trigger_ssm_command(ssm))

    # --- Sigma replay through the real CloudTrail table -------------------------------------------
    s3 = session.client("s3", config=CFG)
    bucket = out(o, "cloudtrail_bucket")
    rnd = random.Random(42)
    synthetic, expected = [], {}

    def upload_sigma_events():
        now = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=30)
        for conv in (c for c in ts.lab_rules().values() if "athena" in c):
            hand, _, _ = ts.case_events(ts.LAB_EXPECTATIONS[conv["slug"]])
            rand, _ = ts.random_events(conv, 50, rnd)
            for ev in hand + rand:
                n = len(synthetic)
                ev = dict(ev, eventTime=(now - timedelta(seconds=n)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                          userAgent=f"e2e-synthetic/{p}/{n}", eventID=f"e2e-synthetic-{n}")
                synthetic.append(ev)
        for slug, conv in ts.lab_rules().items():
            if "athena" in conv:
                assert not any(lf[1] == "userAgent" for lf in ts.leaves(conv["ir"], [])), slug
                expected[slug] = {i for i, ev in enumerate(synthetic) if ts.ref_eval(conv["ir"], ev)}
        by_day = {}
        for ev in synthetic:
            by_day.setdefault(ev["eventTime"][:10], []).append(ev)
        for i, events in enumerate(by_day.values()):
            key, body = lc.cloudtrail_object(account, region, events, f"e2esynthetic{i}")
            s3.put_object(Bucket=bucket, Key=key, Body=body)
        return f"{len(synthetic)} synthetic events in {len(by_day)} file(s)"

    def sigma_hunts_match_reference():
        problems = {}
        for slug, want in expected.items():
            rows = athena.query(named(f"{slug}:"))
            got = {int(r["useragent"].rsplit("/", 1)[1]) for r in rows
                   if (r.get("useragent") or "").startswith(f"e2e-synthetic/{p}/")}
            if got != want:
                problems[slug] = {"missing": sorted(want - got)[:10], "unexpected": sorted(got - want)[:10]}
        assert not problems, json.dumps(problems)
        return f"{len(expected)} Sigma hunts == reference on {len(synthetic)} events"

    checks.run("sigma: synthetic CloudTrail files uploaded", upload_sigma_events)
    checks.run("sigma: Athena hunts match the reference implementation", sigma_hunts_match_reference)

    # --- alarms via SNS ---------------------------------------------------------------------------------------
    def expected_alarms_fire():
        want = {f"{p}-{a}" for a in EXPECTED_ALARMS}
        lc.wait_until(lambda: want <= lc.alarm_names_in_alarm(alerts.snapshot()), ALARM_TIMEOUT, 30,
                      f"ALARM notifications for {sorted(want - lc.alarm_names_in_alarm(alerts.snapshot()))}")
        return ", ".join(sorted(EXPECTED_ALARMS))

    checks.run("alarms reach SNS for every trigger", expected_alarms_fire)

    # --- hunts over S3 data (CloudTrail and Firehose delivery) -------------------------------------------------
    def hunt_returns(prefix, predicate, what):
        sql = named(prefix)
        return lc.wait_until(lambda: [r for r in athena.query(sql) if predicate(r)], DELIVERY_TIMEOUT, 120, what)

    checks.run("hunt 05 finds the access key created for another user", lambda: hunt_returns(
        "05_iam_persistence:", lambda r: r.get("target_user") == target_user and r["finding"].startswith("1"),
        "hunt 05 finding")[0]["finding"])
    checks.run("Sigma hunt finds the SSM SendCommand", lambda: len(hunt_returns(
        "sigma_ssm_command_by_human:", lambda r: r.get("eventname") == "SendCommand"
        and not (r.get("useragent") or "").startswith("e2e-synthetic/"), "Sigma SSM hunt row")))
    checks.run("DNS lake has Parquet rows", lambda: lc.wait_until(
        lambda: int(athena.query(f'SELECT count(*) AS n FROM "{database}"."resolver_query_logs" '
                                 "WHERE dt >= date_format(current_date - interval '1' day, '%Y/%m/%d')")[0]["n"]),
        DELIVERY_TIMEOUT, 120, "rows in resolver_query_logs"))
    checks.run("hunt 23 finds the intel canary", lambda: hunt_returns(
        "23_intel_dns_matches:", lambda r: r.get("indicator") == "intel-canary.invalid", "canary match")[0]["query_name"])

    def no_failed_hunts():
        failed = lc.failed_hunts(alerts.snapshot())
        assert not failed, failed
        return "none"

    checks.run("no scheduled hunt reported FAILED", no_failed_hunts)

    for fn in reversed(cleanup):
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - cleanup is best effort; the janitor sweeps leftovers
            print(f"cleanup: {e}")
    checks.write(args.report)
    print(checks.markdown())
    sys.exit(0 if checks.ok else 1)


if __name__ == "__main__":
    main()
