#!/usr/bin/env python3
"""
Data-flow tests for the scheduled-hunts state machine.

Renders modules/scheduled-hunts/statemachine.asl.json.tftpl the way Terraform
does and runs it with a small interpreter for exactly the ASL features it uses
(Map, Task, Pass, Choice, Parameters, ResultSelector, ResultPath, Catch,
States.ArrayLength / States.Format / States.JsonToString). Service calls are
mocked with responses shaped like the documented Athena and SNS API outputs.

Any JSONPath that does not resolve raises, as Step Functions would at run time
(States.Runtime), so a typo such as $.QueryExecution.Statistic fails here
instead of in your account. Schema validity is checked separately with
asl-validator (see docs/validation.md).

    pip install -r tests/scheduled/requirements.txt
    python3 tests/scheduled/test_state_machine.py
"""
import copy
import json
import pathlib
import re
import sys
import traceback

from jsonpath_ng import parse as jp

ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "modules" / "scheduled-hunts" / "statemachine.asl.json.tftpl"
TOPIC = "arn:aws:sns:eu-west-1:111122223333:detlab-alerts"


def render():
    text = TEMPLATE.read_text()
    for k, v in {"partition": "aws", "workgroup": "detlab-threat-hunting", "name_prefix": "detlab",
                 "topic_arn": TOPIC, "max_concurrency": 2, "sample_rows": 5, "max_results": 6}.items():
        text = text.replace("${" + k + "}", str(v))
    assert "${" not in text, "unrendered template variable"
    return json.loads(text)


class TaskError(Exception):
    def __init__(self, error, cause):
        super().__init__(error)
        self.error, self.cause = error, cause


# --- Minimal ASL (JSONPath mode) interpreter -----------------------------------

def get(path, data):
    matches = jp(path).find(data)
    if not matches:
        raise KeyError(f"States.Runtime: path {path} not found")
    return matches[0].value


def intrinsic(expr, data):
    name, args = re.match(r"^(States\.\w+)\((.*)\)$", expr, re.S).groups()
    parts = [a.strip() for a in re.findall(r"'(?:\\'|[^'])*'|[^,]+", args)]
    vals = [a[1:-1] if a.startswith("'") else get(a, data) for a in parts]
    if name == "States.ArrayLength":
        return len(vals[0])
    if name == "States.JsonToString":
        return json.dumps(vals[0], separators=(",", ":"))
    if name == "States.Format":
        out = vals[0]
        for v in vals[1:]:
            out = out.replace("{}", str(v), 1)
        return out
    raise NotImplementedError(name)


def resolve(template, data):
    if isinstance(template, dict):
        out = {}
        for k, v in template.items():
            if k.endswith(".$"):
                out[k[:-2]] = intrinsic(v, data) if v.startswith("States.") else get(v, data)
            else:
                out[k] = resolve(v, data)
        return out
    return template


def apply_result_path(state, inp, result):
    rp = state.get("ResultPath", "$")
    if rp is None:
        return inp
    if rp == "$":
        return result
    out = copy.deepcopy(inp)
    out[rp[2:]] = result
    return out


def run_states(machine, inp, mocks, calls):
    states, name = machine["States"], machine["StartAt"]
    trace = []
    while True:
        st = states[name]
        trace.append(name)
        nxt = st.get("Next")
        if st["Type"] == "Map":
            for item in get(st["ItemsPath"], inp):
                run_states(st["ItemProcessor"], item, mocks, calls)
            out = apply_result_path(st, inp, None)
        elif st["Type"] == "Task":
            params = resolve(st.get("Parameters", {}), inp)
            try:
                raw = mocks(st["Resource"], params)
                calls.append((st["Resource"], params))
                result = resolve(st["ResultSelector"], raw) if "ResultSelector" in st else raw
                out = apply_result_path(st, inp, result)
            except TaskError as e:
                catch = next(c for c in st.get("Catch", []) if "States.ALL" in c["ErrorEquals"] or e.error in c["ErrorEquals"])
                out = apply_result_path(catch, inp, {"Error": e.error, "Cause": e.cause})
                nxt = catch["Next"]
        elif st["Type"] == "Pass":
            result = resolve(st["Parameters"], inp) if "Parameters" in st else st.get("Result", inp)
            out = apply_result_path(st, inp, result)
        elif st["Type"] == "Choice":
            out = inp
            nxt = st["Default"]
            for c in st["Choices"]:
                if "NumericGreaterThan" in c and get(c["Variable"], inp) > c["NumericGreaterThan"]:
                    nxt = c["Next"]
                    break
        else:
            raise NotImplementedError(st["Type"])
        if st.get("End"):
            return trace, out
        inp, name = out, nxt


# --- Mocks shaped like the real API responses --------------------------------------

SCHEDULER_INPUT = {"hunts": [
    {"name": "05_iam_persistence", "title": "IAM persistence", "attack": "T1098.001", "namedQueryId": "nq-05"},
    {"name": "06_defense_evasion_sensor_tampering", "title": "Sensor tampering", "attack": "T1562.008", "namedQueryId": "nq-06"},
]}


def make_mocks(rows_by_query, fail=()):
    def mock(resource, p):
        if resource.endswith("aws-sdk:athena:getNamedQuery"):
            return {"NamedQuery": {"Name": p["NamedQueryId"], "Database": "detlab_security",
                                   "QueryString": f"SELECT 1 -- {p['NamedQueryId']}", "NamedQueryId": p["NamedQueryId"],
                                   "WorkGroup": "detlab-threat-hunting"}}
        if resource.endswith("athena:startQueryExecution.sync"):
            assert p["WorkGroup"] == "detlab-threat-hunting" and p["QueryExecutionContext"]["Database"] == "detlab_security"
            qid = p["QueryString"].split("-- ")[1]
            if qid in fail:
                raise TaskError("States.TaskFailed", "Query exhausted resources: bytes scanned limit exceeded")
            return {"QueryExecution": {"QueryExecutionId": f"exec-{qid}", "Query": p["QueryString"],
                                       "Status": {"State": "SUCCEEDED"},
                                       "Statistics": {"DataScannedInBytes": 123456, "EngineExecutionTimeInMillis": 900},
                                       "ResultConfiguration": {"OutputLocation": f"s3://results/results/exec-{qid}.csv"}}}
        if resource.endswith("athena:getQueryResults"):
            assert p["MaxResults"] == 6
            qid = p["QueryExecutionId"].removeprefix("exec-")
            header = {"Data": [{"VarCharValue": "findings_total"}, {"VarCharValue": "eventname"}]}
            data = [{"Data": [{"VarCharValue": str(len(rows_by_query.get(qid, [])))}, {"VarCharValue": r}]}
                    for r in rows_by_query.get(qid, [])][:5]
            return {"ResultSet": {"Rows": [header] + data, "ResultSetMetadata": {"ColumnInfo": []}}, "UpdateCount": 0}
        if resource.endswith("sns:publish"):
            assert p["TopicArn"] == TOPIC and len(p["Subject"]) <= 100
            json.loads(p["Message"])  # alerts are machine-readable JSON
            return {"MessageId": "m-1"}
        raise AssertionError(f"unexpected resource {resource}")
    return mock


def publishes(calls):
    return [p for r, p in calls if r.endswith("sns:publish")]


# --- Tests -------------------------------------------------------------------------------

def test_findings_alert_once_with_full_count():
    calls = []
    rows = {"nq-05": [f"CreateAccessKey-{i}" for i in range(7)]}   # 7 findings, alert samples 5
    run_states(render(), SCHEDULER_INPUT, make_mocks(rows), calls)
    pubs = publishes(calls)
    assert [p["Subject"] for p in pubs] == ["[detlab] hunt findings: 05_iam_persistence"], pubs
    msg = json.loads(pubs[0]["Message"])
    assert msg["findings_total"] == "7" and len(msg["sample_rows_including_header"]) == 6, msg
    assert msg["query_execution_id"] == "exec-nq-05" and msg["results_csv"].endswith("exec-nq-05.csv"), msg
    assert msg["attack"] == "T1098.001" and msg["bytes_scanned"] == 123456, msg


def test_clean_run_is_silent():
    calls = []
    trace, _ = run_states(render(), SCHEDULER_INPUT, make_mocks({}), calls)
    assert publishes(calls) == [], publishes(calls)
    assert sum(1 for r, _ in calls if r.endswith("startQueryExecution.sync")) == 2   # both hunts still ran


def test_failed_hunt_alerts_and_others_still_run():
    calls = []
    rows = {"nq-06": ["StopLogging"]}
    run_states(render(), SCHEDULER_INPUT, make_mocks(rows, fail={"nq-05"}), calls)
    subjects = sorted(p["Subject"] for p in publishes(calls))
    assert subjects == ["[detlab] hunt FAILED: 05_iam_persistence",
                        "[detlab] hunt findings: 06_defense_evasion_sensor_tampering"], subjects
    failure = json.loads(next(p["Message"] for p in publishes(calls) if "FAILED" in p["Subject"]))
    assert failure["error"] == "States.TaskFailed" and "bytes scanned" in failure["cause"], failure


def test_map_discards_item_outputs():
    _, out = run_states(render(), SCHEDULER_INPUT, make_mocks({"nq-05": ["x"]}), [])
    assert out == SCHEDULER_INPUT, "Map should not accumulate per-hunt state (256 KB state limit)"


def test_scheduler_input_shape_matches_module():
    src = (ROOT / "modules" / "scheduled-hunts" / "main.tf").read_text()
    for field in ("name", "title", "attack", "namedQueryId"):
        assert re.search(rf"\b{field}\s*=", src), f"scheduler input lacks {field}"
    referenced = set(re.findall(r'"\$\.(name|title|attack|namedQueryId)"', TEMPLATE.read_text()))
    assert referenced <= {"name", "title", "attack", "namedQueryId"}, referenced


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {name}\n{traceback.format_exc()}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
