#!/usr/bin/env python3
"""
Offline tests for the live harness (tests/live/), so its logic is proven before
it runs against AWS:

  * the Athena conformance query builders give Python's answers in DuckDB
  * the catalogue samples agree with the CloudWatch model for JSON patterns
    (patterns rendered by ci/render-catalogue; skipped if Terraform is absent)
  * every AWS API call the harness makes passes botocore's parameter
    validation against the real API models (Stubber)
  * helpers: CloudTrail log files, SNS parsing, janitor selection
  * the live workflows keep their safety properties (always destroy, never
    cancel mid-run, OIDC only, timeouts, one sandbox at a time)

    python3 tests/live/test_harness_offline.py
"""
import gzip
import io
import ipaddress
import json
import os
import pathlib
import random
import shutil
import subprocess
import sys
import tempfile
import traceback
from datetime import datetime, timedelta, timezone

import boto3
import duckdb
import sqlglot
import yaml
from botocore.stub import ANY, Stubber

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import live_common as lc   # noqa: E402

import catalogue_samples   # noqa: E402
import janitor             # noqa: E402
import test_ip_keys as tk  # noqa: E402
import test_sigma as ts    # noqa: E402

ROOT = lc.ROOT


def duck(sql):
    return duckdb.sql(sqlglot.transpile(sql, read="athena", write="duckdb")[0]).fetchall()


def client(service):
    return boto3.client(service, region_name="eu-west-1", aws_access_key_id="x", aws_secret_access_key="x")


# --- Conformance query builders ---------------------------------------------------------------

def test_conformance_queries_reproduce_python_in_duckdb():
    rnd = random.Random(1)
    tk.RND.seed(1)
    texts = sorted({tk.rand_v4() for _ in range(50)} | {str(tk.rand_v6()) for _ in range(50)} | {"::", "it's bad"})
    got = dict(duck(lc.ip_key_query(texts)))
    assert all(got[t] == tk.py_key(t) for t in texts if t != "it's bad") and got["it's bad"] is None
    nets = [ipaddress.ip_network(f"{tk.rand_v6()}/{rnd.randint(0, 128)}", strict=False) for _ in range(40)]
    rows = {c: (lo, hi) for c, lo, hi in duck(lc.ranges_query([str(n) for n in nets]))}
    assert all(rows[str(n)] == (tk.py_key(str(n.network_address)), tk.py_key(str(n.broadcast_address))) for n in nets)
    pairs = [(str(n), str(n.network_address)) for n in nets] + [(str(n), str(n.broadcast_address)) for n in nets]
    res = duck(lc.membership_query(pairs))
    assert len(res) == len(pairs) and all(h == "true" for *_, h in res)
    assert len(lc.ip_key_query(texts * 10)) < 262144, "conformance query must fit Athena's 256 KiB limit"


# --- Catalogue samples vs the CloudWatch model ---------------------------------------------------

def render_catalogue():
    if os.environ.get("CATALOGUE_PLAN"):
        return json.load(open(os.environ["CATALOGUE_PLAN"]))
    if not shutil.which("terraform"):
        return None
    d = ROOT / "ci" / "render-catalogue"
    subprocess.run(["terraform", f"-chdir={d}", "init", "-input=false"], check=True, capture_output=True)
    plan = pathlib.Path(tempfile.mkdtemp()) / "plan.bin"
    subprocess.run(["terraform", f"-chdir={d}", "plan", "-input=false", f"-out={plan}"], check=True, capture_output=True)
    shown = subprocess.run(["terraform", f"-chdir={d}", "show", "-json", str(plan)], check=True, capture_output=True)
    return json.loads(shown.stdout)


def test_catalogue_samples_agree_with_the_model():
    plan = render_catalogue()
    if plan is None:
        print("  SKIP: terraform not available and CATALOGUE_PLAN not set")
        return
    pats = {r["change"]["after"]["name"].split("-", 1)[1]: r["change"]["after"]["pattern"]
            for r in plan["resource_changes"] if r["type"] == "aws_cloudwatch_log_metric_filter"}
    assert set(pats) == set(catalogue_samples.SAMPLES), set(pats) ^ set(catalogue_samples.SAMPLES)
    for name, cases in catalogue_samples.SAMPLES.items():
        assert any(c[1] for c in cases) and any(not c[1] for c in cases), f"{name} needs a positive and a negative"
        if pats[name].startswith("{"):                       # JSON patterns: the model applies
            tree = ts.cwl_parse(pats[name])
            for msg, expected, note in cases:
                assert ts.cwl_eval(tree, json.loads(msg)) == expected, (name, note, msg[:120])
        else:                                                 # space-delimited (flow logs): 22 fields
            for msg, _, _ in cases:
                assert len(msg.split()) == len(catalogue_samples.FLOW_FIELDS) == pats[name].count(",") + 1, name


def test_sigma_conformance_cases_are_unique_and_consistent():
    import test_conformance as tc
    rnd = random.Random(3)
    conv = ts.lab_rules()["sigma_ssm_command_by_human"]
    cases = tc.sigma_cases(conv, rnd)
    msgs = [c[0] for c in cases]
    assert len(set(msgs)) == len(msgs), "messages must be unique (matches are keyed by message)"
    assert sum(c[1] for c in cases) >= 3 and sum(not c[1] for c in cases) >= 3


# --- AWS API calls pass botocore validation (Stubber) ---------------------------------------------

def test_metric_filter_calls_are_valid_and_batched():
    logs = client("logs")
    msgs = [json.dumps({"n": i}) for i in range(120)]
    with Stubber(logs) as stub:
        for batch in lc.chunks(msgs, 50):
            stub.add_response("test_metric_filter", {"matches": [{"eventNumber": 1, "eventMessage": batch[0]}]},
                              {"filterPattern": "{ $.n = 0 }", "logEventMessages": batch})
        bad = lc.compare_with_service(logs, "{ $.n = 0 }", [(m, m == msgs[0], "") for m in msgs])
    # the stub claims each batch's first message matched: messages 50 and 100 are unexpected matches
    assert [b[0] for b in bad] == [msgs[50], msgs[100]], bad


def test_athena_wrapper_calls_are_valid():
    ath = client("athena")
    with Stubber(ath) as stub:
        stub.add_response("start_query_execution", {"QueryExecutionId": "q1"},
                          {"QueryString": "SELECT 1", "WorkGroup": "wg", "QueryExecutionContext": {"Database": "db"}})
        stub.add_response("get_query_execution", {"QueryExecution": {"Status": {"State": "SUCCEEDED"}}},
                          {"QueryExecutionId": "q1"})
        stub.add_response("get_query_results", {"ResultSet": {
            "ResultSetMetadata": {"ColumnInfo": [{"Name": "n", "Type": "varchar"}]},
            "Rows": [{"Data": [{"VarCharValue": "n"}]}, {"Data": [{"VarCharValue": "7"}]}, {"Data": [{}]}]}},
            {"QueryExecutionId": "q1"})
        rows = lc.Athena(ath, "wg", "db").query("SELECT 1")
    assert rows == [{"n": "7"}, {"n": None}], rows
    with Stubber(ath) as stub:
        stub.add_response("list_named_queries", {"NamedQueryIds": ["a", "b"]}, {"WorkGroup": "wg"})
        stub.add_response("batch_get_named_query", {"NamedQueries": [
            {"Name": "01_x: t", "Database": "db", "QueryString": "SELECT 1", "NamedQueryId": "a"},
            {"Name": "sigma_y: t", "Database": "db", "QueryString": "SELECT 2", "NamedQueryId": "b"}],
            "UnprocessedNamedQueryIds": []}, {"NamedQueryIds": ["a", "b"]})
        assert lc.saved_queries(ath, "wg") == {"01_x: t": "SELECT 1", "sigma_y: t": "SELECT 2"}
    with Stubber(ath) as stub:
        stub.add_response("start_query_execution", {"QueryExecutionId": "q2"}, {"QueryString": "bad", "WorkGroup": "wg"})
        stub.add_response("get_query_execution", {"QueryExecution": {"Status": {
            "State": "FAILED", "StateChangeReason": "SYNTAX_ERROR"}}}, {"QueryExecutionId": "q2"})
        try:
            lc.Athena(ath, "wg").query("bad")
            raise AssertionError("a failed query must raise")
        except lc.AthenaError as e:
            assert "SYNTAX_ERROR" in str(e)


class FakeSession:
    def __init__(self, clients):
        self.clients = clients

    def client(self, name, **_):
        return self.clients[name]


def test_alert_subscription_calls_are_valid():
    import test_e2e as te
    sqs, sns = client("sqs"), client("sns")
    topic = "arn:aws:sns:eu-west-1:111122223333:e2e-1-1-alerts"
    url = "https://sqs.eu-west-1.amazonaws.com/111122223333/e2e-1-1-e2e-alerts"
    qarn = "arn:aws:sqs:eu-west-1:111122223333:e2e-1-1-e2e-alerts"
    with Stubber(sqs) as sq, Stubber(sns) as sn:
        sq.add_response("create_queue", {"QueueUrl": url}, {"QueueName": "e2e-1-1-e2e-alerts", "tags": ANY})
        sq.add_response("get_queue_attributes", {"Attributes": {"QueueArn": qarn}},
                        {"QueueUrl": url, "AttributeNames": ["QueueArn"]})
        sq.add_response("set_queue_attributes", {}, {"QueueUrl": url, "Attributes": ANY})
        sn.add_response("subscribe", {"SubscriptionArn": topic + ":sub"},
                        {"TopicArn": topic, "Protocol": "sqs", "Endpoint": qarn, "ReturnSubscriptionArn": True})
        a = te.Alerts(FakeSession({"sqs": sqs, "sns": sns}), topic, "e2e-1-1")
        sq.assert_no_pending_responses()
        sn.assert_no_pending_responses()
    assert a.sub_arn == topic + ":sub" and a.queue_url == url


def test_trigger_and_orchestration_calls_are_valid():
    import test_e2e as te
    ec2, iam, ssm, sfn, sch, s3 = (client(n) for n in ("ec2", "iam", "ssm", "stepfunctions", "scheduler", "s3"))
    with Stubber(ec2) as st:
        st.add_response("create_security_group", {"GroupId": "sg-1"},
                        {"GroupName": "e2e-1-1-e2e-sg", "Description": "e2e trigger", "VpcId": "vpc-1"})
        st.add_response("delete_security_group", {}, {"GroupId": "sg-1"})
        assert te.trigger_security_group(ec2, "e2e-1-1", "vpc-1") == "sg-1"
    with Stubber(iam) as st:
        st.add_response("create_user", {"User": {"Path": "/", "UserName": "e2e-1-1-target", "UserId": "AIDAEXAMPLEUSER00001",
                        "Arn": "arn:aws:iam::111122223333:user/e2e-1-1-target", "CreateDate": datetime.now(timezone.utc)}},
                        {"UserName": "e2e-1-1-target", "Tags": [{"Key": "Purpose", "Value": "e2e"}]})
        st.add_response("create_access_key", {"AccessKey": {"UserName": "e2e-1-1-target", "AccessKeyId": "AKIAEXAMPLE000000001",
                        "Status": "Active", "SecretAccessKey": "s"}}, {"UserName": "e2e-1-1-target"})
        st.add_response("delete_access_key", {}, {"UserName": "e2e-1-1-target", "AccessKeyId": "AKIAEXAMPLE000000001"})
        te.trigger_access_key_for_other_user(iam, "e2e-1-1-target")
    with Stubber(ssm) as st:
        st.add_client_error("send_command", "InvalidInstanceId", expected_params={
            "DocumentName": "AWS-RunShellScript", "InstanceIds": ["i-0e2e0000000000000"], "Parameters": {"commands": ["true"]}})
        assert "InvalidInstanceId" in te.trigger_ssm_command(ssm)
    machine = "arn:aws:states:eu-west-1:111122223333:stateMachine:e2e-1-1-scheduled-hunts"
    ex = "arn:aws:states:eu-west-1:111122223333:execution:e2e-1-1-scheduled-hunts:x"
    with Stubber(sfn) as st:
        st.add_response("list_executions", {"executions": [{"executionArn": ex, "stateMachineArn": machine, "name": "x",
                        "status": "RUNNING", "startDate": datetime.now(timezone.utc)}]}, {"stateMachineArn": machine})
        st.add_response("describe_execution", {"executionArn": ex, "stateMachineArn": machine, "status": "RUNNING",
                        "startDate": datetime.now(timezone.utc), "input": '{"hunts":[{"name":"retro/22_x"}]}'},
                        {"executionArn": ex})
        assert te.find_retro_execution(sfn, machine) == ex
    with Stubber(sfn) as st, Stubber(sch) as sc_:
        target_input = json.dumps({"hunts": [{"name": "05_x"}, {"name": "06_y"}]})
        sc_.add_response("get_schedule", {"Name": "e2e-1-1-daily-hunts", "Target": {"Arn": machine, "RoleArn":
                         "arn:aws:iam::111122223333:role/r", "Input": target_input}}, {"Name": "e2e-1-1-daily-hunts"})
        st.add_response("start_execution", {"executionArn": ex, "startDate": datetime.now(timezone.utc)},
                        {"stateMachineArn": machine, "name": "e2e-manual-1700000000", "input": target_input})
        assert te.start_scheduled_run(sfn, sch, machine, "e2e-1-1", now=1700000000) == (ex, 2)
    with Stubber(s3) as st:
        key, body = lc.cloudtrail_object("111122223333", "eu-west-1", [ts.base_event(0)], "e2esynthetic0")
        st.add_response("put_object", {}, {"Bucket": "b", "Key": key, "Body": body})
        s3.put_object(Bucket="b", Key=key, Body=body)
    # And validation really happens: even when a test's expected params repeat the
    # same typo as the code, botocore rejects the call against the API model.
    with Stubber(sch) as st:
        st.add_response("get_schedule", {"Name": "x", "Target": {"Arn": machine, "RoleArn": "arn:aws:iam::1:role/r"}},
                        {"Nme": "x"})
        try:
            sch.get_schedule(Nme="x")
            raise AssertionError("a misnamed parameter must be rejected")
        except AssertionError:
            raise
        except Exception as e:                       # botocore ParamValidationError
            assert "Unknown parameter" in str(e), e


class FakeLogs:
    """In-memory CloudWatch Logs + Logs Insights for the conformance check. Every call's
    parameters are validated against the real API model. `bool_mode` and
    `null_present` let it misbehave like a service whose undocumented behaviour
    differs from the model's PROBE assumptions."""

    def __init__(self, bool_mode="number", null_present=False):
        import botocore.session
        self.model = botocore.session.get_session().get_service_model("logs")
        self.bool_mode, self.null_present = bool_mode, null_present
        self.groups, self.queries, self.calls = {}, {}, []

    def _validate(self, op, params):
        from botocore.validate import validate_parameters
        validate_parameters(params, self.model.operation_model(op).input_shape)
        self.calls.append(op)

    def create_log_group(self, **kw):
        self._validate("CreateLogGroup", kw)
        self.groups[kw["logGroupName"]] = []

    def put_retention_policy(self, **kw):
        self._validate("PutRetentionPolicy", kw)

    def create_log_stream(self, **kw):
        self._validate("CreateLogStream", kw)

    def put_log_events(self, **kw):
        self._validate("PutLogEvents", kw)
        self.groups[kw["logGroupName"]] += [json.loads(e["message"]) for e in kw["logEvents"]]

    def delete_log_group(self, **kw):
        self._validate("DeleteLogGroup", kw)
        del self.groups[kw["logGroupName"]]

    def _eval(self, node, ev):
        k = node[0]
        if k in ("and", "or"):
            return (all if k == "and" else any)(self._eval(x, ev) for x in node[1])
        if k == "not":
            return not self._eval(node[1], ev)
        v = ts.get_path(ev, node[1])
        present = v is not ts.MISSING and (v is not None or self.null_present)
        if k == "present":
            return present
        if not present or v is None:
            return False
        if k == "eq" and isinstance(v, bool):
            want = node[2]
            if self.bool_mode == "number":
                return isinstance(want, int) and int(v) == want
            if self.bool_mode == "string":
                return isinstance(want, str) and want == ("true" if v else "false")
            return False
        return ts.li_eval(node, ev)

    def start_query(self, **kw):
        self._validate("StartQuery", kw)
        group, q = self.groups[kw["logGroupNames"][0]], kw["queryString"]
        if q.startswith("stats count(*)"):
            rows = [[{"field": "n", "value": str(len(group))}]]
        else:
            cond = q.split("| filter ", 1)[1].rsplit("\n| limit", 1)[0]
            tree = ts.li_parse(cond)
            rows = [[{"field": "eventID", "value": e["eventID"]}] for e in group if self._eval(tree, e)]
        qid = f"q{len(self.queries)}"
        self.queries[qid] = rows
        return {"queryId": qid}

    def get_query_results(self, **kw):
        self._validate("GetQueryResults", kw)
        return {"status": "Complete", "results": self.queries[kw["queryId"]]}


def test_insights_conformance_check_passes_and_fails_correctly():
    import test_conformance as tc
    ok = FakeLogs()                                     # behaves as the model assumes
    detail = tc.check_insights(ok)
    assert "service == model" in detail and "number 1: True" in detail, detail
    assert not ok.groups, "the throwaway log group must be deleted"
    assert {"CreateLogGroup", "PutLogEvents", "StartQuery", "GetQueryResults", "DeleteLogGroup"} <= set(ok.calls)

    detail = tc.check_insights(FakeLogs(bool_mode="string"))   # the dual-form boolean emission covers this
    assert 'string "true": True' in detail, detail

    for fake, needle in ((FakeLogs(bool_mode="neither"), "PROBE boolean"), (FakeLogs(null_present=True), "PROBE null")):
        try:
            tc.check_insights(fake)
            raise AssertionError(f"conformance must fail when the service differs ({needle})")
        except AssertionError as e:
            assert needle in str(e), str(e)[:300]
        assert not fake.groups, "the log group is deleted even when the check fails"


def test_insights_helpers_batch_and_parse():
    logs = FakeLogs()
    logs.create_log_group(logGroupName="/g")
    lc.put_events(logs, "/g", "s", [json.dumps({"eventID": str(i)}) for i in range(2500)], 1_760_000_000_000)
    assert logs.calls.count("PutLogEvents") == 3 and len(logs.groups["/g"]) == 2500
    for conv in ts.lab_rules().values():
        q = lc.insights_rule_query(conv["insights"]["filter"])
        ts.li_parse(q.split("| filter ", 1)[1].rsplit("\n| limit", 1)[0])
        assert len(conv["insights"]["saved_query"]) <= 10000


def test_alarm_names_from_body_or_subject():
    msgs = [("ALARM: \"e2e-1-1-insights-sigma_x\" in EU (Ireland)", "free text, not JSON"),
            ("OK: \"e2e-1-1-y\" in EU (Ireland)", "x")]
    assert lc.alarm_names_in_alarm(msgs) == {"e2e-1-1-insights-sigma_x"}


# --- Helpers ---------------------------------------------------------------------------------------------

def test_cloudtrail_object_is_a_valid_log_file():
    events = [ts.base_event(i) for i in range(3)]
    key, body = lc.cloudtrail_object("111122223333", "eu-west-1", events, "e2esynthetic0")
    day = events[0]["eventTime"][:10].replace("-", "/")
    assert key.startswith(f"AWSLogs/111122223333/CloudTrail/eu-west-1/{day}/") and key.endswith(".json.gz"), key
    assert json.loads(gzip.decompress(body)) == {"Records": events}
    try:
        lc.cloudtrail_object("1", "r", [dict(events[0], eventTime="2026-01-01T00:00:00Z"), events[1]], "x")
        raise AssertionError("events spanning days must be rejected")
    except AssertionError as e:
        assert "several days" in str(e)


def test_sns_parsing():
    alarm = json.dumps({"Subject": "ALARM: x", "Message": json.dumps({"AlarmName": "e2e-1-1-dns_onion_lookup",
                                                                        "NewStateValue": "ALARM"})})
    ok = json.dumps({"Subject": "OK: x", "Message": json.dumps({"AlarmName": "e2e-1-1-x", "NewStateValue": "OK"})})
    failed = json.dumps({"Subject": "[e2e-1-1] hunt FAILED: 05_iam_persistence", "Message": "{}"})
    msgs = [lc.parse_sns_envelope(b) for b in (alarm, ok, failed)]
    assert lc.alarm_names_in_alarm(msgs) == {"e2e-1-1-dns_onion_lookup"}
    assert lc.failed_hunts(msgs) == ["[e2e-1-1] hunt FAILED: 05_iam_persistence"]


def test_janitor_selects_only_stale_e2e_states():
    now = datetime.now(timezone.utc)
    objs = [{"Key": "e2e/e2e-123-1/terraform.tfstate", "LastModified": now - timedelta(hours=7)},
            {"Key": "e2e/e2e-124-1/terraform.tfstate", "LastModified": now - timedelta(hours=1)},     # still running
            {"Key": "e2e/e2e-125-2/terraform.tfstate.tflock", "LastModified": now - timedelta(hours=9)},
            {"Key": "bootstrap/terraform.tfstate", "LastModified": now - timedelta(days=30)},        # not e2e
            {"Key": "e2e/prod/terraform.tfstate", "LastModified": now - timedelta(days=30)}]          # not a run prefix
    assert janitor.stale_prefixes(objs, now - timedelta(hours=6)) == ["e2e-123-1"]


# --- Workflow safety invariants ------------------------------------------------------------------------------

def workflow(name):
    data = yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text())
    data["on"] = data.pop(True, data.get("on"))      # YAML 1.1 reads the key `on` as True
    return data


def test_live_workflows_keep_their_safety_properties():
    live, jan, tests = workflow("live.yml"), workflow("live-janitor.yml"), workflow("tests.yml")
    assert "workflow_call" in tests["on"], "offline suite must be reusable as the live gate"
    for wf in (live, jan):
        assert wf["permissions"] == {"contents": "read", "id-token": "write"}, "OIDC only, least privilege"
        assert wf["concurrency"] == {"group": "aws-sandbox", "cancel-in-progress": False}, "one sandbox user, never cancel"
        assert "pull_request" not in wf["on"] and "push" not in wf["on"], "never on untrusted triggers"
    jobs = live["jobs"]
    assert jobs["conformance"]["needs"] == "offline" and "offline" in jobs["e2e"]["needs"]
    for name in ("conformance", "e2e"):
        assert jobs[name]["environment"] == "sandbox" and jobs[name]["timeout-minutes"] <= 180
    steps = {s.get("id") or s.get("name"): s for s in jobs["e2e"]["steps"]}
    destroy = steps["destroy"]
    assert destroy["if"].startswith("always()") and "terraform destroy" in destroy["run"]
    assert "-var-file=ci/e2e.tfvars" in destroy["run"] and "-var-file=ci/e2e.tfvars" in steps["apply"]["run"]
    assert all("aws-access-key-id" not in json.dumps(s) for s in jobs["e2e"]["steps"] + jobs["conformance"]["steps"])
    assert jan["jobs"]["janitor"]["environment"] == "sandbox"


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {name}\n{traceback.format_exc()[-2000:]}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
