"""
Shared helpers for the live tiers (tests/live/test_conformance.py and
tests/live/test_e2e.py). Pure helpers here are also exercised offline by
tests/live/test_harness_offline.py, so the query builders and parsers are
proven before they ever run against AWS.
"""
import gzip
import io
import json
import pathlib
import re
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parents[2]
for p in ("scripts", "tests/hunts", "tests/sigma", "tests/live"):
    sys.path.insert(0, str(ROOT / p))

TEST_METRIC_FILTER_BATCH = 50          # logs:TestMetricFilter accepts 1-50 events per call (API model)


# --- Result collection and reporting --------------------------------------------------

class Checks:
    """Run named checks, never stopping at the first failure, and write a report."""

    def __init__(self, title):
        self.title, self.results = title, []

    def run(self, name, fn):
        started = time.time()
        try:
            detail = fn() or "ok"
            ok = True
        except Exception as e:  # noqa: BLE001 - every failure is reported, not raised
            detail = f"{type(e).__name__}: {e}"
            ok = False
            traceback.print_exc()
        self.results.append({"check": name, "ok": ok, "seconds": round(time.time() - started, 1), "detail": str(detail)})
        print(f"{'PASS' if ok else 'FAIL'}  {name}  ({self.results[-1]['seconds']}s)  {str(detail)[:300]}", flush=True)
        return ok

    @property
    def ok(self):
        return all(r["ok"] for r in self.results)

    def markdown(self):
        lines = [f"## {self.title}", "", f"{sum(r['ok'] for r in self.results)}/{len(self.results)} checks passed", "",
                 "| Check | Result | Seconds | Detail |", "|-------|--------|---------|--------|"]
        for r in self.results:
            detail = r["detail"].replace("|", "\\|").replace("\n", " ")[:400]
            lines.append(f"| {r['check']} | {'pass' if r['ok'] else '**FAIL**'} | {r['seconds']} | {detail} |")
        return "\n".join(lines) + "\n"

    def write(self, path):
        path = pathlib.Path(path)
        path.write_text(self.markdown())
        path.with_suffix(".json").write_text(json.dumps(self.results, indent=2))


def wait_until(fn, timeout, interval, what):
    """Poll fn() until it returns a truthy value; raise TimeoutError naming `what`."""
    deadline, last = time.time() + timeout, None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(interval)
    raise TimeoutError(f"timed out after {timeout}s waiting for {what} (last: {str(last)[:200]})")


def chunks(items, size):
    return [items[i:i + size] for i in range(0, len(items), size)]


# --- CloudWatch Logs: real TestMetricFilter vs expectations --------------------------------

def test_metric_filter_matches(logs, pattern, messages):
    """Messages the real CloudWatch Logs service says the pattern matches."""
    matched = set()
    unique = list(dict.fromkeys(messages))
    for batch in chunks(unique, TEST_METRIC_FILTER_BATCH):
        resp = logs.test_metric_filter(filterPattern=pattern, logEventMessages=batch)
        matched |= {m["eventMessage"] for m in resp.get("matches", [])}
    return matched


def compare_with_service(logs, pattern, cases):
    """cases: [(message, expected_bool, note)]. Returns disagreements."""
    matched = test_metric_filter_matches(logs, pattern, [c[0] for c in cases])
    return [(msg[:160], expected, note) for msg, expected, note in cases if (msg in matched) != expected]


# --- Athena ---------------------------------------------------------------------------------

class AthenaError(RuntimeError):
    pass


class Athena:
    def __init__(self, client, workgroup, database=None):
        self.client, self.workgroup, self.database = client, workgroup, database

    def start(self, sql, database=None):
        kwargs = {"QueryString": sql, "WorkGroup": self.workgroup}
        db = database or self.database
        if db:
            kwargs["QueryExecutionContext"] = {"Database": db}
        return self.client.start_query_execution(**kwargs)["QueryExecutionId"]

    def wait(self, qid, timeout=900):
        def done():
            st = self.client.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
            return st if st["State"] in ("SUCCEEDED", "FAILED", "CANCELLED") else None
        st = wait_until(done, timeout, 2, f"Athena query {qid}")
        if st["State"] != "SUCCEEDED":
            raise AthenaError(f"{st['State']}: {st.get('StateChangeReason', '')[:500]}")
        return qid

    def rows(self, qid):
        out, columns = [], None
        for page in self.client.get_paginator("get_query_results").paginate(QueryExecutionId=qid):
            rs = page["ResultSet"]
            if columns is None:
                columns = [c["Name"] for c in rs["ResultSetMetadata"]["ColumnInfo"]]
            for row in rs["Rows"]:
                values = [d.get("VarCharValue") for d in row["Data"]]
                if values == columns and not out:
                    continue                        # header row of a SELECT
                out.append(dict(zip(columns, values)))
        return out

    def query(self, sql, database=None, timeout=900):
        return self.rows(self.wait(self.start(sql, database), timeout))

    def run_all(self, named, workers=4):
        """named: {name: sql}. Returns {name: error or None}."""
        def one(item):
            name, sql = item
            try:
                self.wait(self.start(sql))
                return name, None
            except Exception as e:  # noqa: BLE001
                return name, f"{type(e).__name__}: {e}"
        with ThreadPoolExecutor(workers) as pool:
            return dict(pool.map(one, named.items()))


def saved_queries(athena_client, workgroup):
    ids = []
    for page in athena_client.get_paginator("list_named_queries").paginate(WorkGroup=workgroup):
        ids += page["NamedQueryIds"]
    out = {}
    for batch in chunks(ids, 50):
        for q in athena_client.batch_get_named_query(NamedQueryIds=batch)["NamedQueries"]:
            out[q["Name"]] = q["QueryString"]
    return out


# --- Athena conformance query builders (also run offline in DuckDB) ---------------------------

def sql_literal(s):
    return "'" + str(s).replace("'", "''") + "'"


def ip_key_expr():
    return (ROOT / "modules/threat-hunting/sql/ip_key.sql").read_text().strip()


def ranges_cte(src, dst):
    import test_hunts as th
    return th._fill((ROOT / "modules/threat-hunting/sql/cidr_ranges.sql.tftpl").read_text(),
                    {"src": src, "dst": dst, "ip_key": ip_key_expr()}).strip()


def ip_key_query(values):
    rows = ", ".join(f"({sql_literal(v)})" for v in values)
    return f"SELECT v, {ip_key_expr().replace('IP_IN', 'v')} AS k FROM (VALUES {rows}) AS t (v)"


def ranges_query(cidrs):
    rows = ", ".join(f"({sql_literal(c)})" for c in cidrs)
    return f"WITH inp (cidr_text) AS (VALUES {rows}),\n{ranges_cte('inp', 'r')}\nSELECT cidr_text, lo, hi FROM r"


def membership_query(pairs):
    rows = ", ".join(f"({sql_literal(n)}, {sql_literal(a)})" for n, a in pairs)
    key = ip_key_expr().replace("IP_IN", "a")
    return (f"WITH inp (cidr_text, a) AS (VALUES {rows}),\n{ranges_cte('inp', 'r')}\n"
            f"SELECT cidr_text, a, CASE WHEN {key} BETWEEN lo AND hi THEN 'true' ELSE 'false' END AS hit FROM r")


# --- Synthetic CloudTrail files (replayed through the real table in the e2e tier) -----------------

def cloudtrail_object(account, region, events, tag):
    """(key, gzip bytes) for a CloudTrail-format log file holding `events`.
    All events must share one UTC day; the key is in that day's partition."""
    days = {e["eventTime"][:10] for e in events}
    assert len(days) == 1, f"events span several days: {sorted(days)}"
    y, m, d = days.pop().split("-")
    key = (f"AWSLogs/{account}/CloudTrail/{region}/{y}/{m}/{d}/"
           f"{account}_CloudTrail_{region}_{y}{m}{d}T0000Z_{tag}.json.gz")
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(json.dumps({"Records": events}).encode())
    return key, buf.getvalue()


# --- SNS alert collection ----------------------------------------------------------------------------

def parse_sns_envelope(body):
    """SQS body from an SNS subscription -> (subject, parsed message or raw string)."""
    env = json.loads(body)
    msg = env.get("Message", "")
    try:
        msg = json.loads(msg)
    except (TypeError, ValueError):
        pass
    return env.get("Subject") or "", msg


ALARM_SUBJECT = re.compile(r'^ALARM: "(.+?)" in ')


def alarm_names_in_alarm(messages):
    """Alarm names that reached ALARM, from the JSON body (metric alarms) or the
    standard subject line, so log alarms count whichever format they use."""
    names = set()
    for subject, m in messages:
        if isinstance(m, dict) and m.get("NewStateValue") == "ALARM" and m.get("AlarmName"):
            names.add(m["AlarmName"])
        hit = ALARM_SUBJECT.match(subject or "")
        if hit:
            names.add(hit.group(1))
    return names


def failed_hunts(messages):
    return sorted(s for s, _ in messages if "hunt FAILED:" in s)


# --- CloudWatch Logs Insights -------------------------------------------------------------------

PUT_LOG_EVENTS_BATCH = 1000            # well under the API's 10,000-event / 1 MB per-call limits


def put_events(logs, group, stream, messages, start_ms):
    """Write messages as log events with strictly increasing timestamps."""
    events = [{"timestamp": start_ms + i, "message": m} for i, m in enumerate(messages)]
    for batch in chunks(events, PUT_LOG_EVENTS_BATCH):
        logs.put_log_events(logGroupName=group, logStreamName=stream, logEvents=batch)


def insights_query(logs, group, query, start_s, end_s, timeout=300):
    """Run a Logs Insights query; return rows as dicts."""
    qid = logs.start_query(logGroupNames=[group], startTime=int(start_s), endTime=int(end_s),
                           queryString=query, limit=10000)["queryId"]

    def done():
        r = logs.get_query_results(queryId=qid)
        return r if r["status"] not in ("Scheduled", "Running") else None
    r = wait_until(done, timeout, 2, f"Logs Insights query {qid}")
    if r["status"] != "Complete":
        raise RuntimeError(f"Logs Insights query {r['status']}: {query[:200]}")
    return [{f["field"]: f["value"] for f in row} for row in r["results"]]


def insights_rule_query(condition):
    return f"fields eventID\n| filter {condition}\n| limit 10000"
