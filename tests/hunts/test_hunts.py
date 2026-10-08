#!/usr/bin/env python3
"""
Behavioural tests for the Athena threat-hunting queries.

Each test plants an attack in synthetic CloudTrail data next to benign
look-alikes, runs the real hunt, and asserts it finds the attack and nothing
else. Queries are rendered exactly as Terraform renders them, transpiled from
Athena (Trino) SQL to DuckDB with sqlglot, and run in-process: no AWS needed.

The table schema is parsed from modules/threat-hunting/main.tf, so these tests
fail if the Glue table and the queries drift apart.

    pip install -r tests/hunts/requirements.txt
    python3 tests/hunts/test_hunts.py

What this proves: query logic (joins, windows, thresholds, exclusions) and
column/field references. What it cannot prove: Athena-specific behaviour such
as partition-projection pruning, or exact Trino function edge cases.
"""
import json
import pathlib
import re
import sys
import tempfile
import traceback
from datetime import datetime, timedelta, timezone

import duckdb
import sqlglot

ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "threat-hunting"
LAKE = ROOT / "modules" / "network-log-lake"
DB, TABLE, FLOW, DNS = "detlab_security", "cloudtrail", "vpc_flow_logs", "resolver_query_logs"
ACCT = "111122223333"
NOW = datetime.now(timezone.utc).replace(microsecond=0)
BASELINE = NOW - timedelta(days=10)
RECENT = NOW - timedelta(hours=2)
# Start of an hour safely inside the recent window, for hour-bucketed hunts.
HOUR = (NOW - timedelta(hours=3)).replace(minute=0, second=0)


# --- Schema: parsed from the module so test and table cannot drift -----------

def _split_top(s, sep=","):
    out, depth, cur = [], 0, ""
    for ch in s:
        depth += ch == "<"
        depth -= ch == ">"
        if ch == sep and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    return out + [cur]


def glue_to_duckdb(t):
    t = t.strip()
    if t == "string":
        return "VARCHAR"
    if t in ("int", "bigint"):
        return {"int": "INTEGER", "bigint": "BIGINT"}[t]
    if t.startswith("struct<"):
        fields = []
        for f in _split_top(t[7:-1]):
            name, typ = f.split(":", 1)
            fields.append(f'"{name}" {glue_to_duckdb(typ)}')
        return f"STRUCT({', '.join(fields)})"
    if t.startswith("array<"):
        return glue_to_duckdb(t[6:-1]) + "[]"
    if t.startswith("map<"):
        k, v = _split_top(t[4:-1])
        return f"MAP({glue_to_duckdb(k)}, {glue_to_duckdb(v)})"
    raise ValueError(f"unhandled Glue type: {t}")


def module_schema():
    src = (MODULE / "main.tf").read_text()
    types = {}
    m = re.search(r"useridentity = <<-T\n(.*?)\n\s*T\n", src, re.S)
    types["useridentity"] = re.sub(r"\s+", "", m.group(1))
    for name in ("resources", "addendum", "tlsdetails"):
        types[name] = re.search(rf'{name}\s*=\s*"([^"]+)"', src).group(1)
    cols = []
    for name, simple, ref in re.findall(r'\["(\w+)",\s*(?:"(\w+)"|local\.t\.(\w+))\]', src):
        cols.append((name, simple if simple else types[ref]))
    assert len(cols) == 29, f"expected 29 CloudTrail columns, parsed {len(cols)}"
    return cols + [("region", "string"), ("dt", "string")]


def lake_schema(list_name):
    """Columns of flow_columns / dns_columns in modules/network-log-lake/main.tf."""
    src = (LAKE / "main.tf").read_text()
    block = re.search(rf"{list_name} = \[(.*?)\n  \]", src, re.S).group(1)
    cols = re.findall(r'\["(\w+)",\s*"([^"]+)"\]', block)
    assert cols, f"no columns parsed for {list_name}"
    return cols + [("dt", "string")]


SCHEMAS = {TABLE: module_schema, FLOW: lambda: lake_schema("flow_columns"), DNS: lambda: lake_schema("dns_columns")}


# --- Rendering: same substitutions Terraform's templatefile() makes ----------

def _fill(template, values):
    for k, v in values.items():
        template = template.replace("${" + k + "}", str(v))
    assert "${" not in template, "unrendered template variable"
    return template


def render_athena(name, lookback_days=30, recent_days=1):
    return _fill((MODULE / "queries" / f"{name}.sql").read_text(),
                 {"database": DB, "table": TABLE, "flow_table": FLOW, "dns_table": DNS,
                  "lookback_days": lookback_days, "recent_days": recent_days})


def render(name, lookback_days=30, recent_days=1):
    return sqlglot.transpile(render_athena(name, lookback_days, recent_days), read="athena", write="duckdb")[0]


def header(name, key):
    m = re.search(rf"(?m)^-- {key}:(.*)$", (MODULE / "queries" / f"{name}.sql").read_text())
    return m.group(1).strip() if m else None


LAG_HOURS = 1


def render_scheduled_athena(name):
    """Mirror of local.scheduled in modules/threat-hunting/main.tf."""
    baseline = header(name, "schedule-baseline") == "true"
    inner = render_athena(name, lookback_days=30 if baseline else 2, recent_days=2).strip()
    return _fill((MODULE / "scheduled_wrapper.sql.tftpl").read_text(), {
        "name": name, "time_column": header(name, "schedule-time-column"),
        "start_hours": 24 + LAG_HOURS, "end_hours": LAG_HOURS, "inner": inner})


def render_scheduled(name):
    return sqlglot.transpile(render_scheduled_athena(name), read="athena", write="duckdb")[0]


def schedulable():
    return sorted(p.stem for p in (MODULE / "queries").glob("*.sql") if header(p.stem, "schedule-time-column"))


# --- Synthetic CloudTrail --------------------------------------------------------

def user(name, key=None):
    return {"type": "IAMUser", "principalid": f"AIDA{name.upper()}", "accountid": ACCT,
            "arn": f"arn:aws:iam::{ACCT}:user/{name}", "username": name,
            "accesskeyid": key or f"AKIA{name.upper():0<16}"[:20]}


def role_session(role, session, acct=ACCT, principal_suffix=None, imds=None):
    return {"type": "AssumedRole", "accountid": acct,
            "principalid": f"AROA{role.upper()}:{principal_suffix or session}",
            "arn": f"arn:aws:sts::{acct}:assumed-role/{role}/{session}",
            "accesskeyid": f"ASIA{role.upper():0<16}"[:20],
            "sessioncontext": {"sessionissuer": {"type": "Role", "arn": f"arn:aws:iam::{acct}:role/{role}",
                                                 "accountid": acct, "username": role},
                               "ec2roledelivery": imds}}


ROOT_ID = {"type": "Root", "principalid": ACCT, "arn": f"arn:aws:iam::{ACCT}:root", "accountid": ACCT}


def ev(name, source, at, ident, ip="198.51.100.10", err=None, req=None, resp=None,
       add=None, readonly=None, region="eu-west-1", etype="AwsApiCall", ua="aws-cli/2.17"):
    return {
        "eventtime": at.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventname": name, "eventsource": source,
        "useridentity": ident, "sourceipaddress": ip, "errorcode": err, "awsregion": region,
        "requestparameters": json.dumps(req, separators=(",", ":")) if req is not None else None,
        "responseelements": json.dumps(resp, separators=(",", ":")) if resp is not None else None,
        "additionaleventdata": json.dumps(add, separators=(",", ":")) if add is not None else None,
        "readonly": readonly if readonly is not None else str(name.startswith(("List", "Describe", "Get"))).lower(),
        "eventtype": etype, "recipientaccountid": ACCT, "useragent": ua,
        "region": region, "dt": at.strftime("%Y/%m/%d"),
    }


FIXTURES = {}


def flow(at, src, dst, dport, *, instance="i-0web", action="ACCEPT", direction="egress", nbytes=1000,
         sport=40000, aws_service=None):
    epoch = int(at.timestamp())
    return {"__table": FLOW, "version": 5, "account_id": ACCT, "interface_id": "eni-1", "srcaddr": src,
            "dstaddr": dst, "srcport": sport, "dstport": dport, "protocol": 6, "packets": 10, "bytes": nbytes,
            "start": epoch, "end": epoch + 60, "action": action, "log_status": "OK", "vpc_id": "vpc-1",
            "subnet_id": "subnet-1", "instance_id": instance, "tcp_flags": 2, "type": "IPv4",
            "pkt_srcaddr": src, "pkt_dstaddr": dst, "flow_direction": direction,
            "pkt_src_aws_service": None, "pkt_dst_aws_service": aws_service, "traffic_path": 8,
            "dt": at.strftime("%Y/%m/%d")}


def dns(at, instance, name, qtype="A", rcode="NOERROR", answers=(), firewall=None):
    return {"__table": DNS, "version": "1.100000", "account_id": ACCT, "region": "eu-west-1", "vpc_id": "vpc-1",
            "query_timestamp": at.strftime("%Y-%m-%dT%H:%M:%SZ"), "query_name": name + ".", "query_type": qtype,
            "query_class": "IN", "rcode": rcode,
            "answers": [{"rdata": a, "type": "A", "class": "IN"} for a in answers],
            "srcaddr": "10.42.1.10", "srcport": "53000", "transport": "UDP",
            "srcids": {"instance": instance, "resolver_endpoint": None},
            "firewall_rule_action": firewall, "firewall_rule_group_id": None, "firewall_domain_list_id": None,
            "dt": at.strftime("%Y/%m/%d")}


def run(name, events, **render_kw):
    FIXTURES[name] = events
    return run_sql(render(name, **render_kw), events)


def run_sql(sql, events):
    """events: dicts; a "__table" key routes them to flow or dns (default CloudTrail)."""
    con = duckdb.connect()
    con.execute("SET TimeZone = 'UTC'")
    con.execute(f"CREATE SCHEMA {DB}")
    for table, schema_fn in SCHEMAS.items():
        schema = schema_fn()
        cols = ", ".join(f'"{n}" {glue_to_duckdb(t)}' for n, t in schema)
        con.execute(f"CREATE TABLE {DB}.{table} ({cols})")
        rows = [{k: v for k, v in e.items() if k != "__table"} for e in events if e.get("__table", TABLE) == table]
        if rows:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
                for r in rows:
                    fh.write(json.dumps(r) + "\n")
            spec = ", ".join(f"'{n}': '{glue_to_duckdb(t)}'" for n, t in schema)
            con.execute(f"INSERT INTO {DB}.{table} SELECT * FROM read_json('{fh.name}', "
                        f"format='newline_delimited', columns={{{spec}}})")
    cur = con.execute(sql)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, row)) for row in cur.fetchall()]


# --- Tests ---------------------------------------------------------------------------

def login(at, ident, ip, outcome="Success", mfa="Yes"):
    return ev("ConsoleLogin", "signin.amazonaws.com", at, ident, ip,
              err=None if outcome == "Success" else "Failed authentication",
              resp={"ConsoleLogin": outcome}, add={"MFAUsed": mfa}, readonly="false")


def test_01_console_login_new_source():
    alice, bob = user("alice"), user("bob")
    rows = run("01_console_login_new_source", [
        login(BASELINE, alice, "198.51.100.10"), login(RECENT, alice, "198.51.100.10"),  # known IP
        login(BASELINE, bob, "198.51.100.20"), login(RECENT, bob, "203.0.113.66", mfa="No"),  # new IP
    ])
    assert {(r["identity"], r["sourceipaddress"]) for r in rows} == {(bob["arn"], "203.0.113.66")}, rows


def test_02_console_bruteforce_then_success():
    t = lambda m: HOUR + timedelta(minutes=m)
    events = [login(t(1 + i), {"type": "IAMUser", "username": u}, "203.0.113.50", "Failure")
              for i, u in enumerate(["carol", "dave", "erin", "frank", "grace", "carol"])]
    events.append(login(t(20), user("carol"), "203.0.113.50"))                       # spray lands
    events += [login(t(2), user("heidi"), "198.51.100.30", "Failure"),
               login(t(3), user("heidi"), "198.51.100.30")]                          # typo then ok
    events += [login(t(5 + i), {"type": "IAMUser", "username": "x"}, "192.0.2.9", "Failure")
               for i in range(10)]                                                   # never succeeded
    rows = run("02_console_bruteforce_then_success", events)
    assert [r["sourceipaddress"] for r in rows] == ["203.0.113.50"], rows
    assert rows[0]["failures"] == 6 and rows[0]["identities_tried"] >= 5, rows


def test_03_permission_probing():
    thief = user("ci-bot", key="AKIATHIEF00000000000")
    apis = ["ListUsers", "ListRoles", "GetAccountAuthorizationDetails", "ListBuckets", "DescribeInstances",
            "ListFunctions", "ListSecrets", "DescribeDBInstances", "ListKeys", "GetCallerIdentity",
            "ListTopics", "DescribeVpcs"]
    events = [ev(a, "iam.amazonaws.com", HOUR + timedelta(minutes=i), thief, "203.0.113.7", err="AccessDenied")
              for i, a in enumerate(apis)]
    events += [ev(a, "s3.amazonaws.com", HOUR + timedelta(minutes=i), user("dev"), err="AccessDenied")
               for i, a in enumerate(["GetObject", "PutObject", "ListBucket"])]
    rows = run("03_permission_probing", events)
    assert [r["access_key"] for r in rows] == ["AKIATHIEF00000000000"] and rows[0]["distinct_apis"] == 12, rows


def test_04_enumeration_burst():
    attacker = role_session("app-role", "pacu")
    services = ["ec2", "iam", "s3", "lambda", "rds", "kms", "secretsmanager"]
    events = [ev(f"Describe{svc.title()}Thing{i}", f"{svc}.amazonaws.com", HOUR + timedelta(seconds=i * 20),
                 attacker, "203.0.113.8") for i, svc in enumerate(services * 5)]
    # AWS Config enumerating on your behalf: exceeds BOTH thresholds (60 APIs, 7
    # services), so only the *.amazonaws.com source exclusion can remove it.
    events += [ev(f"DescribeConfigItem{i}", f"{services[i % 7]}.amazonaws.com", HOUR + timedelta(seconds=i),
                  role_session("config-role", "AWSConfig"), "config.amazonaws.com") for i in range(60)]
    events += [ev(f"List{i}", "s3.amazonaws.com", HOUR + timedelta(minutes=i), user("ops")) for i in range(10)]
    rows = run("04_enumeration_burst", events)
    assert [r["identity"] for r in rows] == [attacker["arn"]], rows
    assert rows[0]["distinct_apis"] == 35 and rows[0]["distinct_services"] == 7, rows


def test_05_iam_persistence():
    mallory, alice = user("mallory"), user("alice")
    rows = run("05_iam_persistence", [
        ev("CreateAccessKey", "iam.amazonaws.com", RECENT, mallory, req={"userName": "svc-backup"}),
        ev("CreateAccessKey", "iam.amazonaws.com", RECENT, alice, req={}),           # own key: low priority
        ev("AttachUserPolicy", "iam.amazonaws.com", RECENT, mallory,
           req={"userName": "mallory", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
        ev("CreateUser", "iam.amazonaws.com", RECENT, mallory, req={"userName": "x"}, err="AccessDenied"),  # failed: excluded
    ])
    findings = [(r["finding"][0], r["eventname"]) for r in rows]
    assert findings == [("1", "CreateAccessKey"), ("2", "AttachUserPolicy"), ("5", "CreateAccessKey")], findings
    assert rows[0]["target_user"] == "svc-backup", rows


def test_06_defense_evasion_sensor_tampering():
    x = user("intruder")
    rows = run("06_defense_evasion_sensor_tampering", [
        ev("StopLogging", "cloudtrail.amazonaws.com", RECENT, x),
        ev("CreateIPSet", "guardduty.amazonaws.com", RECENT, x),                      # trusted-IP allowlisting
        ev("UpdateFirewallConfig", "route53resolver.amazonaws.com", RECENT, x),       # flip DNS Firewall fail-open
        ev("DeleteRule", "events.amazonaws.com", RECENT, x, err="AccessDenied"),      # failed attempt still shown
        ev("DeleteRule", "elasticloadbalancing.amazonaws.com", RECENT, x),            # same name, unrelated service
        ev("CreateTrail", "cloudtrail.amazonaws.com", RECENT, x),
    ])
    got = {(r["sensor"], r["eventname"]) for r in rows}
    assert got == {("CloudTrail", "StopLogging"), ("GuardDuty", "CreateIPSet"),
                   ("Resolver logging / DNS Firewall", "UpdateFirewallConfig"),
                   ("EventBridge routing", "DeleteRule")}, got


def test_07_new_region_activity():
    ops, x = user("ops"), user("intruder")
    rows = run("07_new_region_activity", [
        ev("RunInstances", "ec2.amazonaws.com", BASELINE, ops, region="eu-west-1"),
        ev("RunInstances", "ec2.amazonaws.com", RECENT, ops, region="eu-west-1"),
        ev("RunInstances", "ec2.amazonaws.com", RECENT, x, region="ap-southeast-3"),
        ev("CreateUser", "iam.amazonaws.com", RECENT, x, region="us-east-1"),        # global service: excluded
        ev("DescribeInstances", "ec2.amazonaws.com", RECENT, x, region="sa-east-1"),  # read-only: excluded
    ])
    assert [r["awsregion"] for r in rows] == ["ap-southeast-3"], rows


def test_08_data_shared_to_other_accounts():
    x = user("intruder")
    rows = run("08_data_shared_to_other_accounts", [
        ev("ModifySnapshotAttribute", "ec2.amazonaws.com", RECENT, x,
           req={"snapshotId": "snap-0abc", "createVolumePermission": {"add": {"items": [{"userId": "999988887777"}]}}}),
        ev("PutBucketPolicy", "s3.amazonaws.com", RECENT, x,
           req={"bucketName": "data", "bucketPolicy": {"Statement": [{"Principal": {"AWS": "*"}, "Action": "s3:GetObject"}]}}),
        ev("PutBucketPolicy", "s3.amazonaws.com", RECENT, user("ops"),
           req={"bucketName": "logs", "bucketPolicy": {"Statement": [{"Principal": {"AWS": f"arn:aws:iam::{ACCT}:root"}}]},
                "requestedAt": 1712345678901}),                                         # own account + 13-digit number
    ])
    assert len(rows) == 2, rows
    by_event = {r["eventname"]: r for r in rows}
    assert by_event["ModifySnapshotAttribute"]["foreign_accounts"] == ["999988887777"], rows
    assert by_event["PutBucketPolicy"]["public"] is True, rows


def test_09_compute_hijacking():
    x = user("intruder")
    def launch(itype, count=1, err=None):
        return ev("RunInstances", "ec2.amazonaws.com", RECENT, x, err=err,
                  req={"instanceType": itype, "instancesSet": {"items": [{"imageId": "ami-1", "minCount": 1, "maxCount": count}]}})
    rows = run("09_compute_hijacking", [
        launch("p4d.24xlarge", err="VcpuLimitExceeded"), launch("g5.xlarge"), launch("c5.metal"),
        launch("m5.12xlarge"), launch("t3.micro", 20),                               # flagged
        launch("t3.micro"), launch("m5.2xlarge"), launch("m5.xlarge", 4),            # benign
    ])
    assert sorted((r["instance_type"], r["max_count"]) for r in rows) == sorted(
        [("p4d.24xlarge", 1), ("g5.xlarge", 1), ("c5.metal", 1), ("m5.12xlarge", 1), ("t3.micro", 20)]), rows


def test_10_secret_harvesting():
    harvester, app = role_session("lambda-role", "fn"), role_session("app-role", "svc")
    events = [ev("GetSecretValue", "secretsmanager.amazonaws.com", RECENT, harvester, req={"secretId": f"prod/db{i}"})
              for i in range(6)]
    events += [ev("GetSecretValue", "secretsmanager.amazonaws.com", RECENT, app, req={"secretId": "prod/app"})
               for _ in range(50)]
    events += [ev("GetParameter", "ssm.amazonaws.com", RECENT, app, req={"name": f"/cfg/{i}", "withDecryption": False})
               for i in range(10)]                                                    # not decrypted: excluded
    rows = run("10_secret_harvesting", events)
    assert [r["identity"] for r in rows] == [harvester["arn"]] and rows[0]["distinct_secrets"] == 6, rows


def test_11_instance_credentials_replayed():
    stolen = role_session("web-role", "i-0aaa1111", principal_suffix="i-0aaa1111", imds="1.0")
    normal = role_session("web-role", "i-0bbb2222", principal_suffix="i-0bbb2222", imds="2.0")
    rows = run("11_instance_credentials_replayed", [
        ev("ListBuckets", "s3.amazonaws.com", RECENT, stolen, "198.51.100.7"),
        ev("ListBuckets", "s3.amazonaws.com", RECENT, stolen, "203.0.113.99"),       # replayed elsewhere
        ev("ListBuckets", "s3.amazonaws.com", RECENT, normal, "198.51.100.8"),
        ev("ListBuckets", "s3.amazonaws.com", RECENT, normal, "s3.amazonaws.com"),   # service-originated
    ])
    assert [(r["instance_id"], r["distinct_source_ips"]) for r in rows] == [("i-0aaa1111", 2)], rows
    assert rows[0]["imds_version"] == ["1.0"], rows


def test_12_root_activity():
    svc_root = dict(ROOT_ID, invokedby="support.amazonaws.com")
    rows = run("12_root_activity", [
        login(RECENT, ROOT_ID, "203.0.113.5", mfa="No"),
        ev("CreateAccessKey", "iam.amazonaws.com", RECENT, ROOT_ID),
        ev("DescribeCases", "support.amazonaws.com", RECENT, svc_root),                # invoked by a service
        ev("SomeServiceEvent", "health.amazonaws.com", RECENT, ROOT_ID, etype="AwsServiceEvent"),
    ])
    assert sorted(r["eventname"] for r in rows) == ["ConsoleLogin", "CreateAccessKey"], rows
    assert {r["eventname"]: r["mfa"] for r in rows}["ConsoleLogin"] == "No", rows


def test_13_new_role_assumption_path():
    ci = role_session("ci-role", "build")
    eve = user("eve")
    assume = lambda at, who, role: ev("AssumeRole", "sts.amazonaws.com", at, who,
                                      req={"roleArn": role, "roleSessionName": "s"}, region="us-east-1")
    deploy, prod = f"arn:aws:iam::{ACCT}:role/deploy-role", "arn:aws:iam::444455556666:role/prod-admin"
    rows = run("13_new_role_assumption_path", [
        assume(BASELINE, ci, deploy), assume(RECENT, ci, deploy),                     # known path
        assume(RECENT, eve, prod),                                                     # new, cross-account
    ])
    assert [(r["role_arn"], r["cross_account"]) for r in rows] == [(prod, True)], rows


def test_14_investigate_access_key():
    k = user("leaked", key="AKIAIOSFODNN7EXAMPLE")
    rows = run("14_investigate_access_key", [
        ev("GetCallerIdentity", "sts.amazonaws.com", RECENT, k),
        ev("ListBuckets", "s3.amazonaws.com", RECENT - timedelta(minutes=5), k),
        ev("ListBuckets", "s3.amazonaws.com", RECENT, user("other")),
    ])
    assert [r["eventname"] for r in rows] == ["ListBuckets", "GetCallerIdentity"], rows


def test_15_dns_beaconing():
    start = RECENT - timedelta(minutes=5 * 20)
    events = []
    for i in range(20):                                   # implant: every 300s +/- 3s, A and AAAA together
        t = start + timedelta(seconds=300 * i + (i % 3) - 1)
        events += [dns(t, "i-0beacon", "c2.evil-cdn.net"), dns(t, "i-0beacon", "c2.evil-cdn.net", "AAAA")]
    for i, gap in enumerate([30, 400, 90, 1200, 15, 700, 60, 300, 2000, 45, 500, 120, 900, 20]):
        start += timedelta(seconds=gap)                   # human/app: irregular
        events.append(dns(start, "i-0app", "api.partner.com"))
    for i in range(20):                                   # periodic by design: excluded
        events.append(dns(RECENT - timedelta(minutes=60 * i), "i-0app", "ssm.eu-west-1.amazonaws.com"))
        events.append(dns(RECENT - timedelta(minutes=30 * i), "i-0app", "ip-10-42-1-5.eu-west-1.compute.internal"))
    rows = run("15_dns_beaconing", events)
    assert [(r["instance"], r["domain"]) for r in rows] == [("i-0beacon", "c2.evil-cdn.net")], rows
    assert 295 <= rows[0]["avg_interval_seconds"] <= 305 and rows[0]["jitter"] < 0.05, rows


def test_16_dns_new_rare_domain():
    events = [dns(BASELINE, f"i-0{n}", "www.github.com") for n in "abc"]
    events += [dns(RECENT, "i-0a", "api.github.com"),                       # old, wide domain
               dns(RECENT, "i-0x", "update.qzv81-cdn.top"),                 # new, one instance
               dns(RECENT - timedelta(minutes=5), "i-0x", "cfg.qzv81-cdn.top")]
    events += [dns(RECENT, f"i-0{n}", "login.newsaas.io") for n in "abc"]   # new but wide: not rare
    events += [dns(RECENT, "i-0x", "ip-10-0-0-1.eu-west-1.compute.internal")]  # internal: excluded
    rows = run("16_dns_new_rare_domain", events)
    assert [(r["domain"], r["instance"], r["lookups"]) for r in rows] == [("qzv81-cdn.top", "i-0x", 2)], rows


def test_17_dns_tunnel_shape():
    import random, string
    rnd = random.Random(7)
    label = lambda n: "".join(rnd.choices(string.ascii_lowercase + string.digits, k=n))
    events = [dns(HOUR + timedelta(seconds=20 * i), "i-0tun", f"{label(40)}.t.exfil-dom.com", "TXT") for i in range(80)]
    events += [dns(HOUR + timedelta(seconds=20 * i), "i-0cdn", f"img{i}.static.cdn-site.com") for i in range(60)]  # short labels
    events += [dns(HOUR + timedelta(seconds=60 * i), "i-0few", f"{label(40)}.x.other-dom.com") for i in range(10)]  # too few
    rows = run("17_dns_tunnel_shape", events)
    assert [(r["instance"], r["parent_domain"], r["unique_names"]) for r in rows] == [("i-0tun", "exfil-dom.com", 80)], rows


def test_18_flow_new_external_transfer():
    MiB = 1048576
    rows = run("18_flow_new_external_transfer", [
        flow(BASELINE, "10.42.1.10", "203.0.113.10", 443, instance="i-0web", nbytes=900 * MiB),
        flow(RECENT, "10.42.1.10", "203.0.113.10", 443, instance="i-0web", nbytes=500 * MiB),   # known destination
        flow(RECENT, "10.42.1.20", "198.51.100.200", 443, instance="i-0db", nbytes=180 * MiB),  # new + large
        flow(RECENT, "10.42.1.20", "198.51.100.201", 443, instance="i-0db", nbytes=5 * MiB),    # new but small
        flow(RECENT, "10.42.1.20", "10.42.2.5", 5432, instance="i-0db", nbytes=2000 * MiB),     # internal
        flow(RECENT, "10.42.1.20", "52.95.1.1", 443, instance="i-0db", nbytes=900 * MiB, aws_service="S3"),
        flow(RECENT, "10.42.1.20", "100.64.0.9", 443, instance="i-0db", nbytes=900 * MiB),      # CGNAT range: private
    ])
    assert [(r["instance_id"], r["dstaddr"], r["mib_out"]) for r in rows] == [("i-0db", "198.51.100.200", 180.0)], rows


def test_19_flow_internal_scan():
    events = [flow(HOUR + timedelta(seconds=i), "10.42.1.9", f"10.42.{i // 200}.{i % 200 + 1}", 22,
                   instance="i-0pwned", action="REJECT" if i % 3 else "ACCEPT") for i in range(30)]
    events += [flow(HOUR + timedelta(seconds=i), "10.42.1.9", "10.42.1.50", 1000 + i, instance="i-0pwned") for i in range(5)]
    events += [flow(HOUR + timedelta(minutes=i), "10.42.1.10", f"10.42.1.{i + 60}", 443, instance="i-0web") for i in range(3)]
    events += [flow(HOUR + timedelta(seconds=i), "10.42.1.11", f"198.51.100.{i}", 443, instance="i-0crawler") for i in range(40)]
    rows = run("19_flow_internal_scan", events)
    assert [(r["srcaddr"], r["hosts"]) for r in rows] == [("10.42.1.9", 31)], rows
    assert rows[0]["rejected"] == 20, rows


def test_20_flow_egress_without_dns():
    rows = run("20_flow_egress_without_dns", [
        dns(RECENT - timedelta(minutes=10), "i-0a", "good.example.com", answers=["203.0.113.20"]),
        flow(RECENT, "10.42.1.10", "203.0.113.20", 443, instance="i-0a"),              # resolved first
        flow(RECENT, "10.42.1.10", "198.51.100.66", 8443, instance="i-0a"),            # never resolved
        flow(RECENT, "10.42.1.10", "10.42.9.9", 443, instance="i-0a"),                 # internal
        dns(RECENT - timedelta(days=3), "i-0b", "old.example.com", answers=["203.0.113.77"]),
        flow(RECENT, "10.42.1.11", "203.0.113.77", 443, instance="i-0b"),              # resolved too long ago
        dns(RECENT - timedelta(minutes=5), "i-0c", "x.example.com", answers=["203.0.113.88"]),
        flow(RECENT, "10.42.1.12", "203.0.113.88", 443, instance="i-0d"),              # resolved by ANOTHER instance
    ])
    got = sorted((r["instance_id"], r["dstaddr"]) for r in rows)
    assert got == [("i-0a", "198.51.100.66"), ("i-0b", "203.0.113.77"), ("i-0d", "203.0.113.88")], got


def test_21_investigate_instance():
    me = "i-0123456789abcdef0"
    role = role_session("web-role", me, principal_suffix=me)
    rows = run("21_investigate_instance", [
        ev("RunInstances", "ec2.amazonaws.com", RECENT - timedelta(hours=1), user("ops"),
           req={"instanceType": "t3.micro"}, resp={"instancesSet": {"items": [{"instanceId": me}]}}),
        dns(RECENT - timedelta(minutes=30), me, "c2.evil-cdn.net", firewall="BLOCK"),
        flow(RECENT - timedelta(minutes=20), "10.42.1.10", "198.51.100.66", 8443, instance=me, nbytes=4096),
        ev("ListBuckets", "s3.amazonaws.com", RECENT - timedelta(minutes=10), role, "198.51.100.66"),
        ev("ListBuckets", "s3.amazonaws.com", RECENT, user("other")),               # unrelated
        dns(RECENT, "i-0other", "example.com"), flow(RECENT, "10.42.1.99", "1.1.1.1", 53, instance="i-0other"),
    ])
    assert [r["source"] for r in rows] == ["cloudtrail: about instance", "dns", "flow", "cloudtrail: by instance"], rows
    assert rows[1]["outcome"] == "BLOCK" and "8443" in rows[2]["detail"] and "4096 bytes" in rows[2]["detail"], rows


def shift(events, delta):
    out = []
    for e in events:
        e = dict(e)
        table = e.get("__table", TABLE)
        if table == FLOW:
            e["start"] += int(delta.total_seconds())
            e["end"] += int(delta.total_seconds())
            t = datetime.fromtimestamp(e["start"], timezone.utc)
        else:
            key = "query_timestamp" if table == DNS else "eventtime"
            t = datetime.strptime(e[key], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) + delta
            e[key] = t.strftime("%Y-%m-%dT%H:%M:%SZ")
        e["dt"] = t.strftime("%Y/%m/%d")
        out.append(e)
    return out


def test_scheduled_variants_report_inside_window_only():
    """Every schedulable hunt: same findings as the full hunt when the attack is
    inside today's window, a correct findings_total, and nothing once it is 2 days old."""
    for name in schedulable():
        globals()[f"test_{name}"]()                       # (re)records this hunt's fixture
        events = FIXTURES[name]
        full = run_sql(render(name), events)
        sched = run_sql(render_scheduled(name), events)
        assert len(sched) == len(full) > 0, (name, len(full), len(sched))
        assert all(r["findings_total"] == len(sched) for r in sched), name
        old = run_sql(render_scheduled(name), shift(events, timedelta(days=-2)))
        assert old == [], (name, old)


def test_scheduled_window_edges_report_each_event_exactly_once():
    """Two consecutive daily runs: an event lands in exactly one of them."""
    x = user("intruder")
    mk = lambda ago, tag: ev("CreateAccessKey", "iam.amazonaws.com", NOW - ago, x, req={"userName": tag})
    events = [mk(timedelta(hours=26), "yesterdays-window"), mk(timedelta(hours=2), "todays-window"),
              mk(timedelta(minutes=30), "inside-lag")]
    today = {r["target_user"] for r in run_sql(render_scheduled("05_iam_persistence"), events)}
    tomorrow = {r["target_user"] for r in run_sql(render_scheduled("05_iam_persistence"), shift(events, timedelta(days=-1)))}
    assert today == {"todays-window"}, today
    assert tomorrow == {"inside-lag"}, tomorrow       # held back by the lag today, reported tomorrow
    assert not today & tomorrow                       # never twice


def test_scheduled_sql_parses_as_athena():
    for name in schedulable():
        sqlglot.parse_one(render_scheduled_athena(name), read="athena", error_level=sqlglot.ErrorLevel.RAISE)


def test_only_pivots_are_unschedulable():
    unschedulable = {p.stem for p in (MODULE / "queries").glob("*.sql")} - set(schedulable())
    assert unschedulable == {"14_investigate_access_key", "21_investigate_instance"}, unschedulable


def test_default_schedule_names_only_schedulable_hunts():
    src = (ROOT / "variables.tf").read_text()
    block = re.search(r'variable "scheduled_hunts" \{.*?default = \[(.*?)\]', src, re.S).group(1)
    defaults = re.findall(r'"([0-9]{2}_[a-z0-9_]+)"', block)
    assert defaults and set(defaults) <= set(schedulable()), sorted(set(defaults) - set(schedulable()))


def test_every_query_has_a_test():
    queries = {p.stem for p in (MODULE / "queries").glob("*.sql")}
    tested = {n[5:] for n in globals() if n.startswith("test_") and n[5:7].isdigit()}  # scheduled tests are extra
    assert queries == tested, f"untested: {sorted(queries - tested)}; stale: {sorted(tested - queries)}"


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except Exception:  # noqa: BLE001 - report every failure, not just the first
            failed += 1
            print(f"FAIL  {name}\n{traceback.format_exc()}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
