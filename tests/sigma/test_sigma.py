#!/usr/bin/env python3
"""
Tests for scripts/sigma_convert.py.

Three independent implementations of each rule are compared:

  reference   a direct Python interpreter of Sigma semantics over raw
              CloudTrail JSON (case-insensitive, absent field => false)
  athena      the generated hunt SQL, rendered as Terraform renders it,
              transpiled to DuckDB and run against the CloudTrail table
  cloudwatch  the generated metric-filter pattern, parsed and evaluated by a
              model of the documented CloudWatch JSON filter semantics

Hand-written expectations pin down each lab rule; randomised differential
testing (hundreds of events per rule: absent, null, matching, near-miss and
case-flipped values) checks the three agree. Case-flipped events are excluded
from the CloudWatch comparison only, because CloudWatch is case-sensitive by
design; a dedicated test shows that divergence.

The CloudWatch side is a model of the documentation, not CloudWatch itself.
Negated comparisons are emitted as (!= || NOT EXISTS || IS NULL), so their
meaning does not depend on how CloudWatch treats != on a missing field.

    pip install -r tests/sigma/requirements.txt
    python3 tests/sigma/test_sigma.py
"""
import copy
import ipaddress
import json
import pathlib
import random
import re
import string
import sys
import tempfile
import textwrap
import traceback
from datetime import datetime, timedelta, timezone

import duckdb
import sqlglot

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests" / "hunts"))
import sigma_convert as sc  # noqa: E402
import test_hunts as th     # noqa: E402

NOW = datetime.now(timezone.utc).replace(microsecond=0)
MISSING = object()


# --- Raw event helpers ---------------------------------------------------------------

def get_path(event, field):
    node = event
    for seg in field.split("."):
        if not isinstance(node, dict) or seg not in node:
            return MISSING
        node = node[seg]
    return node


def set_path(event, field, value):
    node = event
    *parents, last = field.split(".")
    for seg in parents:
        node = node.setdefault(seg, {})
    if value is MISSING:
        node.pop(last, None)
    else:
        node[last] = value


def base_event(i=0):
    t = NOW - timedelta(hours=2) + timedelta(seconds=i)
    return {"eventVersion": "1.09", "eventTime": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": "other.amazonaws.com", "eventName": "OtherCall", "awsRegion": "eu-west-1",
            "sourceIPAddress": "198.51.100.200", "userAgent": "aws-cli/2",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/u", "userName": "u"},
            "requestParameters": {}, "responseElements": {}, "eventType": "AwsApiCall",
            "recipientAccountId": "111122223333"}


# --- Reference: Sigma semantics --------------------------------------------------------

def scalar_text(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float, str)):
        return str(v)
    return None


def tokens_regex(tokens, cased):
    rx = "".join({"star": ".*", "q": "."}.get(t[0]) or re.escape(t[1]) for t in tokens)
    return re.compile(rx, re.S if cased else re.S | re.I)


def ref_eval(e, event):
    op = e[0]
    if op == "and":
        return all(ref_eval(x, event) for x in e[1])
    if op == "or":
        return any(ref_eval(x, event) for x in e[1])
    if op == "not":
        return not ref_eval(e[1], event)
    _, field, kind, value, cased = e
    v = get_path(event, field)
    absent = v is MISSING or v is None
    if kind == "null":
        return absent
    if kind == "exists":
        return (not absent) == value
    if absent or isinstance(v, (dict, list)):
        return False
    if kind == "bool":
        return scalar_text(v).lower() == ("true" if value else "false")
    if kind == "int":
        return not isinstance(v, bool) and scalar_text(v) == str(value)
    if kind == "re":
        rx, flags = value
        return re.search(rx, scalar_text(v), re.I if "i" in flags else 0) is not None
    if kind == "cidr":
        try:
            ip = ipaddress.ip_address(scalar_text(v))
        except ValueError:
            return False
        return ip.version == value.version and ip in value
    return tokens_regex(value, cased).fullmatch(scalar_text(v)) is not None


# --- Model of CloudWatch JSON filter patterns (documented semantics) -----------------------

# Tokens: punctuation, quoted strings, selectors, numbers, and bare words (keywords
# such as IS / NOT EXISTS, and unquoted values like the CIS patterns' kms.amazonaws.com).
CWL_TOKEN = re.compile(r'\s*(\{|\}|\(|\)|&&|\|\||!=|=|"(?:[^"\\]|\\.)*"|\$\.[A-Za-z0-9_.-]+'
                       r'|-?\d+(?![A-Za-z0-9_.*:/-])|[A-Za-z0-9_*][A-Za-z0-9_.*:/-]*)')


def cwl_parse(pattern):
    toks, pos = [], 0
    while pos < len(pattern):
        m = CWL_TOKEN.match(pattern, pos)
        if not m:
            if pattern[pos:].strip() == "":
                break
            raise ValueError(f"cannot tokenize at {pattern[pos:pos + 20]!r}")
        toks.append(m.group(1))
        pos = m.end()
    i = 0

    def take(expected=None):
        nonlocal i
        t = toks[i]
        if expected and t != expected:
            raise ValueError(f"expected {expected}, got {t}")
        i += 1
        return t

    def comparison():
        sel = take()
        if not sel.startswith("$."):
            raise ValueError(f"expected selector, got {sel}")
        op = take()
        if op in ("=", "!="):
            val = take()
            if val.startswith('"'):
                val = json.loads(val)
            elif re.fullmatch(r"-?\d+", val):
                val = int(val)                 # unquoted number
            # otherwise an unquoted string (as in the CIS patterns)
            return ("cmp", sel[2:], op, val)
        if op == "IS":
            return ("is", sel[2:], take())
        if op == "NOT":
            take("EXISTS")
            return ("notexists", sel[2:])
        raise ValueError(f"unsupported operator {op}")

    def factor():
        if toks[i] == "(":
            take("(")
            x = expr()
            take(")")
            return x
        return comparison()

    def term():
        parts = [factor()]
        while i < len(toks) and toks[i] == "&&":
            take()
            parts.append(factor())
        return ("and", parts)

    def expr():
        parts = [term()]
        while i < len(toks) and toks[i] == "||":
            take()
            parts.append(term())
        return ("or", parts)

    take("{")
    tree = expr()
    take("}")
    if i != len(toks):
        raise ValueError("trailing tokens")
    return tree


def cwl_glob(pat, text):
    """Case-sensitive; * only at the start and/or end (as the converter emits)."""
    lead, trail = pat.startswith("*"), pat.endswith("*") and len(pat) > 1
    core = pat[1 if lead else 0: len(pat) - (1 if trail else 0)]
    if pat == "*":
        return True
    if lead and trail:
        return core in text
    if lead:
        return text.endswith(core)
    if trail:
        return text.startswith(core)
    return text == core


def cwl_eval(node, event):
    kind = node[0]
    if kind == "and":
        return all(cwl_eval(x, event) for x in node[1])
    if kind == "or":
        return any(cwl_eval(x, event) for x in node[1])
    if kind == "notexists":
        return get_path(event, node[1]) is MISSING
    v = get_path(event, node[1])
    if kind == "is":
        if v is MISSING:
            return False
        return {"NULL": v is None, "TRUE": v is True, "FALSE": v is False}[node[2]]
    _, _, op, val = node
    if v is MISSING or v is None or isinstance(v, (dict, list)):
        return False      # documented: selectors on objects/arrays never match; missing compares false
    if isinstance(val, str):
        if not isinstance(v, str):
            return False
        hit = cwl_glob(val, v)
    else:
        if isinstance(v, bool) or not isinstance(v, int):
            return False
        hit = v == val
    return hit if op == "=" else not hit


# --- Model of CloudWatch Logs Insights (documented semantics + two PROBE assumptions) -------
# Documented: and/or/not; comparisons and functions return booleans; ispresent();
# isIpInSubnet() for IPv4 and IPv6 (true only for a valid address in the subnet);
# `like /regex/` matches anywhere unless anchored; (?i) works; RE2 syntax.
# PROBE (not documented; checked by the live conformance tier): a JSON null field
# counts as not present, and a JSON boolean compares equal to the number 1 / 0.

LI_TOKEN = re.compile(r'\s*(\(|\)|,|=|/(?:\\.|[^/\\])*/|"(?:[^"\\]|\\.)*"|-?\d+(?![A-Za-z_.])|[A-Za-z_@][A-Za-z0-9_.@]*)')


def li_parse(cond):
    toks, pos = [], 0
    while pos < len(cond):
        m = LI_TOKEN.match(cond, pos)
        if not m:
            if not cond[pos:].strip():
                break
            raise ValueError(f"cannot tokenize at {cond[pos:pos + 25]!r}")
        toks.append(m.group(1))
        pos = m.end()
    i = 0

    def take(expected=None):
        nonlocal i
        t = toks[i]
        if expected is not None and t != expected:
            raise ValueError(f"expected {expected}, got {t}")
        i += 1
        return t

    def atom():
        t = take()
        if t == "ispresent":
            take("(")
            f = take()
            take(")")
            return ("present", f)
        if t == "isIpInSubnet":
            take("(")
            f = take()
            take(",")
            net = json.loads(take())
            take(")")
            return ("subnet", f, net)
        op = take()
        val = take()
        if op == "like":
            return ("like", t, val[1:-1].replace("\\/", "/"))
        if op == "=":
            return ("eq", t, json.loads(val) if val.startswith('"') else int(val))
        raise ValueError(f"unsupported {t} {op}")

    def factor():
        if toks[i] == "not":
            take()
            return ("not", factor())
        if toks[i] == "(":
            take("(")
            x = expr()
            take(")")
            return x
        return atom()

    def term():
        parts = [factor()]
        while i < len(toks) and toks[i] == "and":
            take()
            parts.append(factor())
        return ("and", parts)

    def expr():
        parts = [term()]
        while i < len(toks) and toks[i] == "or":
            take()
            parts.append(term())
        return ("or", parts)

    tree = expr()
    if i != len(toks):
        raise ValueError(f"trailing tokens: {toks[i:]}")
    return tree


def li_value(event, field):
    v = get_path(event, field)
    return MISSING if v is None else v          # PROBE: JSON null counts as absent


def li_eval(node, event):
    k = node[0]
    if k == "and":
        return all(li_eval(x, event) for x in node[1])
    if k == "or":
        return any(li_eval(x, event) for x in node[1])
    if k == "not":
        return not li_eval(node[1], event)
    v = li_value(event, node[1])
    if k == "present":
        return v is not MISSING
    if v is MISSING or isinstance(v, (dict, list)):
        return False                             # documented: maps/lists compare false
    if k == "subnet":
        try:
            ip = ipaddress.ip_address(str(v))
        except ValueError:
            return False
        net = ipaddress.ip_network(node[2])
        return ip.version == net.version and ip in net
    if k == "like":
        text = scalar_text(v)
        return re.search(node[2], text) is not None
    want = node[2]
    if isinstance(want, int):
        if isinstance(v, bool):
            return int(v) == want                # PROBE: JSON true/false compare as 1/0
        return isinstance(v, (int, float)) and v == want
    return isinstance(v, str) and v == want


def li_filter(conv):
    return li_parse(conv["insights"]["filter"])


# --- Athena (generated SQL in DuckDB) ----------------------------------------------------

def to_row(event):
    """Raw CloudTrail JSON -> a row of the Glue table (as the JsonSerDe would read it)."""
    def low(d):
        return {k.lower(): low(v) if isinstance(v, dict) else v for k, v in d.items()} if isinstance(d, dict) else d

    row = {}
    for k, v in event.items():
        col = k.lower()
        if k in sc.JSON_COLUMNS:
            row[col] = json.dumps(v)
        elif isinstance(v, dict):
            row[col] = low(v)
        elif isinstance(v, bool):
            row[col] = "true" if v else "false"
        elif v is None:
            row[col] = None
        else:
            row[col] = str(v)
    t = datetime.strptime(event["eventTime"], "%Y-%m-%dT%H:%M:%SZ")
    row.update(region=event.get("awsRegion", "eu-west-1"), dt=t.strftime("%Y/%m/%d"))
    return row


def athena_matches(hunt_sql, events):
    sql = th._fill(hunt_sql, {"database": th.DB, "table": th.TABLE, "lookback_days": 30, "ip_key": th.ip_key()})
    duck = sqlglot.transpile(sql, read="athena", write="duckdb")[0]
    con = duckdb.connect()
    con.execute("SET TimeZone = 'UTC'")
    con.execute(f"CREATE SCHEMA {th.DB}")
    schema = th.module_schema()
    cols = ", ".join(f'"{n}" {th.glue_to_duckdb(t)}' for n, t in schema)
    con.execute(f"CREATE TABLE {th.DB}.{th.TABLE} ({cols})")
    if events:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            for ev in events:
                fh.write(json.dumps(to_row(ev)) + "\n")
        spec = ", ".join(f"'{n}': '{th.glue_to_duckdb(t)}'" for n, t in schema)
        con.execute(f"INSERT INTO {th.DB}.{th.TABLE} SELECT * FROM read_json('{fh.name}', "
                    f"format='newline_delimited', columns={{{spec}}})")
    hit_times = {r[0].strftime("%Y-%m-%dT%H:%M:%SZ") for r in con.execute(duck).fetchall()}
    return [ev["eventTime"] in hit_times for ev in events]


# --- Running a rule through all three ---------------------------------------------------------

def convert_text(yaml_text, name="rule.yml"):
    d = pathlib.Path(tempfile.mkdtemp())
    (d / name).write_text(textwrap.dedent(yaml_text))
    return sc.convert_rule(d / name)


def lab_rules():
    return {r["slug"]: r for r in sc.convert_all()}


def evaluate(conv, events):
    ref = [ref_eval(conv["ir"], ev) for ev in events]
    ath = athena_matches(conv["hunt_sql"], events) if "hunt_sql" in conv else None
    cw = [cwl_eval(cwl_parse(conv["cloudwatch"]), ev) for ev in events] if "cloudwatch" in conv else None
    if "insights" in conv:
        tree = li_filter(conv)
        li = [li_eval(tree, ev) for ev in events]
        assert li == ref, ("logs insights disagrees with reference", conv["slug"],
                           [(events[i], ref[i], li[i]) for i in range(len(ref)) if li[i] != ref[i]][:2])
    return ref, ath, cw


def case_events(cases):
    """(changes, expected[, cloudwatch_expected]) cases -> (events, expected, cloudwatch_expected)."""
    events, want, want_cw = [], [], []
    for i, case in enumerate(cases):
        ev = base_event(i)
        for f, v in case[0].items():
            set_path(ev, f, v)
        events.append(ev)
        want.append(case[1])
        want_cw.append(case[2] if len(case) > 2 else case[1])
    return events, want, want_cw


def check_expectations(conv, cases):
    """cases: (changes, expected) or (changes, expected, cloudwatch_expected) where
    CloudWatch differs by design (case sensitivity)."""
    events, want, want_cw = [], [], []
    for i, case in enumerate(cases):
        changes, expected = case[0], case[1]
        ev = base_event(i)
        for f, v in changes.items():
            set_path(ev, f, v)
        events.append(ev)
        want.append(expected)
        want_cw.append(case[2] if len(case) > 2 else expected)
    ref, ath, cw = evaluate(conv, events)
    assert ref == want, ("reference", conv["slug"], ref, want)
    assert ath == want, ("athena", conv["slug"], ath, want)
    if cw is not None:
        assert cw == want_cw, ("cloudwatch", conv["slug"], cw, want_cw)


# --- Hand-written expectations for every lab rule ------------------------------------------------

LAB_EXPECTATIONS = {
    "sigma_guardduty_detector_disabled": [
        ({"eventSource": "guardduty.amazonaws.com", "eventName": "DeleteDetector"}, True),
        ({"eventSource": "guardduty.amazonaws.com", "eventName": "UpdateDetector", "requestParameters.enable": False}, True),
        ({"eventSource": "guardduty.amazonaws.com", "eventName": "UpdateDetector", "requestParameters.enable": True}, False),
        ({"eventSource": "guardduty.amazonaws.com", "eventName": "UpdateDetector"}, False),
        ({"eventSource": "guardduty.amazonaws.com", "eventName": "CreateDetector"}, False),
        ({"eventSource": "guarddutyXamazonaws.com", "eventName": "DeleteDetector"}, False)],    # . is literal
    "sigma_s3_public_access_block_removed": [
        ({"eventSource": "s3.amazonaws.com", "eventName": "DeleteBucketPublicAccessBlock"}, True),
        ({"eventSource": "s3-control.amazonaws.com", "eventName": "DeleteAccountPublicAccessBlock"}, True),
        ({"eventSource": "s3.amazonaws.com", "eventName": "PutBucketPublicAccessBlock"}, False),
        ({"eventSource": "s3.amazonaws.com", "eventName": "DeleteBucketPolicy"}, False)],
    "sigma_iam_root_access_key_created": [
        ({"eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey", "userIdentity.type": "Root"}, True),
        ({"eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey", "userIdentity.type": "IAMUser"}, False)],
    "sigma_ec2_user_data_modified": [
        ({"eventSource": "ec2.amazonaws.com", "eventName": "ModifyInstanceAttribute",
          "requestParameters.userData": "<sensitiveDataRemoved>"}, True),
        ({"eventSource": "ec2.amazonaws.com", "eventName": "ModifyInstanceAttribute",
          "requestParameters.instanceType": {"value": "t3.large"}}, False)],
    "sigma_lambda_function_url_public": [
        ({"eventSource": "lambda.amazonaws.com", "eventName": "CreateFunctionUrlConfig20211031",
          "requestParameters.authType": "NONE"}, True),
        ({"eventSource": "lambda.amazonaws.com", "eventName": "UpdateFunctionUrlConfig20211031",
          "requestParameters.authType": "NONE"}, True),
        ({"eventSource": "lambda.amazonaws.com", "eventName": "CreateFunctionUrlConfig20211031",
          "requestParameters.authType": "AWS_IAM"}, False)],
    "sigma_ssm_command_by_human": [
        ({"eventSource": "ssm.amazonaws.com", "eventName": "SendCommand"}, True),          # invokedBy absent
        ({"eventSource": "ssm.amazonaws.com", "eventName": "StartSession", "userIdentity.invokedBy": None}, True),
        ({"eventSource": "ssm.amazonaws.com", "eventName": "SendCommand",
          "userIdentity.invokedBy": "ssm.amazonaws.com"}, False),
        ({"eventSource": "ssm.amazonaws.com", "eventName": "SendCommand",
          "userIdentity.invokedBy": "evil.example"}, True)],
    "sigma_secretsmanager_resource_policy_changed": [
        ({"eventSource": "secretsmanager.amazonaws.com", "eventName": "PutResourcePolicy"}, True),
        ({"eventSource": "secretsmanager.amazonaws.com", "eventName": "PutResourcePolicy",
          "errorCode": "AccessDenied"}, False),
        ({"eventSource": "secretsmanager.amazonaws.com", "eventName": "GetSecretValue"}, False)],
    "sigma_organizations_leave": [
        ({"eventSource": "organizations.amazonaws.com", "eventName": "LeaveOrganization"}, True),
        ({"eventSource": "organizations.amazonaws.com", "eventName": "ListAccounts"}, False)],
    "sigma_console_login_outside_known_ranges": [
        ({"eventName": "ConsoleLogin", "responseElements.ConsoleLogin": "Success", "sourceIPAddress": "203.0.113.9"}, True),
        ({"eventName": "ConsoleLogin", "responseElements.ConsoleLogin": "Success", "sourceIPAddress": "192.0.2.5"}, False),
        ({"eventName": "ConsoleLogin", "responseElements.ConsoleLogin": "Success", "sourceIPAddress": "2001:db8::1"}, False),
        ({"eventName": "ConsoleLogin", "responseElements.ConsoleLogin": "Success", "sourceIPAddress": "2001:db9::1"}, True),
        ({"eventName": "ConsoleLogin", "responseElements.ConsoleLogin": "Failure", "sourceIPAddress": "203.0.113.9"}, False)],
}


def test_lab_rules_hand_written_expectations():
    rules = lab_rules()
    assert set(LAB_EXPECTATIONS) == set(rules), f"lab rules without expectations: {set(rules) - set(LAB_EXPECTATIONS)}"
    for slug, cases in LAB_EXPECTATIONS.items():
        check_expectations(rules[slug], cases)


# --- Randomised differential testing ---------------------------------------------------------

FIXTURE_RULES = {
    "fx_all_of_them_and_cased": """
        title: fixture all of them, cased, underscore item ignored
        logsource: {product: aws, service: cloudtrail}
        detection:
          sel_a: {eventSource: iam.amazonaws.com}
          sel_b: {eventName|cased: CreateUser}
          _ignored: {eventName: NeverMatches}
          condition: all of them
    """,
    "fx_nested_logic_ints_null": """
        title: fixture nested not/or, int and null
        logsource: {product: aws, service: cloudtrail}
        detection:
          a: {eventName: [RunInstances, StartInstances]}
          b: {requestParameters.maxCount: 5}
          c: {errorCode: null}
          d: {userIdentity.type: Root}
          condition: (a or b) and not (c or d)
    """,
    "fx_all_modifier_and_contains": """
        title: fixture |all and |contains
        logsource: {product: aws, service: cloudtrail}
        detection:
          sel:
            userAgent|contains|all: [aws-cli, Linux]
            eventName|contains: Policy
          condition: sel
    """,
    "fx_exists_and_escape": """
        title: fixture exists false, escaped wildcard, quote
        logsource: {product: aws, service: cloudtrail}
        detection:
          sel:
            userIdentity.sessionContext.sessionIssuer.userName|exists: false
            requestParameters.note: "it's \\\\*literal"
          condition: sel
    """,
    "fx_question_mark_and_regex": """
        title: fixture ? wildcard and |re|i (Athena only)
        logsource: {product: aws, service: cloudtrail}
        detection:
          sel_q: {eventName: 'Delete?rail'}
          sel_re: {eventName|re|i: '^stop(logging|recording)$'}
          sel_lit: {errorMessage: 'what\\?'}
          condition: 1 of sel_*
    """,
    "fx_negated_group_underscore": """
        title: fixture negated group (De Morgan in CloudWatch) and _ inside a wildcard value
        logsource: {product: aws, service: cloudtrail}
        detection:
          a: {eventSource: iam.amazonaws.com, userAgent|startswith: boto3_cli}
          b: {eventName: CreateUser}
          c: {userIdentity.type: Root}
          condition: a and not (b or c)
    """,
    "fx_cidr_mixed_families": """
        title: fixture cidr both families (Athena only)
        logsource: {product: aws, service: cloudtrail}
        detection:
          sel: {sourceIPAddress|cidr: [203.0.113.0/25, '2001:db8:aa00::/40']}
          condition: sel
    """,
}


def fixture(name):
    return convert_text(FIXTURE_RULES[name], f"{name}.yml")


def leaves(e, out):
    if e[0] in ("and", "or"):
        for x in e[1]:
            leaves(x, out)
    elif e[0] == "not":
        leaves(e[1], out)
    else:
        out.append(e)
    return out


def sample_tokens(tokens, rnd):
    alphabet = string.ascii_letters + string.digits + ".-"
    return "".join(rnd.choice(["", "x", "".join(rnd.choices(alphabet, k=rnd.randint(1, 5)))]) if t[0] == "star"
                   else rnd.choice(alphabet) if t[0] == "q" else t[1] for t in tokens)


def candidates_for(field_leaves, rnd):
    """Values for one field: (value, case_variant?) pairs, typed like the rule's leaves."""
    cands = [("zz-other-value", False), ("", False)]
    patterns = [lf for lf in field_leaves if lf[2] == "pattern"]
    if len(patterns) > 1:                      # lets |all (several leaves on one field) be satisfied
        cands.append((" ".join(sample_tokens(lf[3], rnd) for lf in patterns), False))
    for _, _, kind, value, cased in field_leaves:
        if kind == "pattern":
            s = sample_tokens(value, rnd)
            cands += [(s, False), (s + "Q", False), (s[1:] if len(s) > 1 else s + "x", False)]
            confused = s.replace("_", "A").replace("%", "A").replace(".", "X")   # _ % . must not act as wildcards
            if confused != s:
                cands.append((confused, False))
            if not cased and s.swapcase() != s:
                cands.append((s.swapcase(), True))
        elif kind == "bool":
            cands = [(True, False), (False, False)]
        elif kind == "int":
            cands += [(value, False), (value + 1, False)]
        elif kind == "cidr":
            net = value
            inside = net.network_address + rnd.randint(0, min(net.num_addresses - 1, 2 ** 20))
            outside = net.broadcast_address + 1 if int(net.broadcast_address) < 2 ** net.max_prefixlen - 1 else net.network_address - 1
            cands += [(str(inside), False), (str(outside), False), ("192.0.2.1", False), ("2001:db8::1", False)]
        elif kind == "re":
            cands += [("StopLogging", False), ("stoprecording", False), ("StopLoggingNow", False)]
    return cands


def random_events(conv, n, rnd):
    by_field = {}
    for lf in leaves(conv["ir"], []):
        by_field.setdefault(lf[1], []).append(lf)
    pools = {f: candidates_for(ls, rnd) for f, ls in by_field.items()}
    events, variant = [], []
    for i in range(n):
        ev, is_variant = base_event(i), False
        for f, pool in pools.items():
            r = rnd.random()
            if r < 0.12:
                set_path(ev, f, MISSING)
            elif r < 0.2:
                set_path(ev, f, None)
            else:
                v, var = rnd.choice(pool)
                set_path(ev, f, v)
                is_variant |= var
        events.append(ev)
        variant.append(is_variant)
    return events, variant


def differential(conv, n=400, seed=7):
    rnd = random.Random(seed)
    events, variant = random_events(conv, n, rnd)
    ref, ath, cw = evaluate(conv, events)
    assert 3 <= sum(ref) <= n - 3, (conv["slug"], "sample lacks positives or negatives", sum(ref))
    if ath is not None:
        bad = [(events[i], ref[i], ath[i]) for i in range(n) if ref[i] != ath[i]]
        assert not bad, ("athena disagrees with reference", conv["slug"], bad[:2])
    if cw is not None:
        bad = [(events[i], ref[i], cw[i]) for i in range(n) if not variant[i] and ref[i] != cw[i]]
        assert not bad, ("cloudwatch disagrees with reference", conv["slug"], bad[:2])
    return sum(ref)


def test_differential_lab_rules():
    for slug, conv in lab_rules().items():
        differential(conv)


def test_differential_fixture_rules():
    for name in FIXTURE_RULES:
        conv = fixture(name)
        assert "error" not in conv, (name, conv.get("error"))
        differential(conv)


def test_logs_insights_converts_every_fixture_rule():
    """Logs Insights can express every supported construct, unlike metric filters."""
    for name in FIXTURE_RULES:
        conv = fixture(name)
        assert "insights" in conv, (name, conv.get("insights_skipped"))
        assert len(conv["insights"]["saved_query"]) <= sc.INSIGHTS_MAX_QUERY


def test_targets_reported_for_fixtures():
    want = {
        "fx_all_of_them_and_cased": ("cloudwatch", "athena"),
        "fx_nested_logic_ints_null": ("athena",),                       # not null => needs EXISTS
        "fx_all_modifier_and_contains": ("cloudwatch", "athena"),
        "fx_exists_and_escape": ("athena",),                            # literal * cannot be expressed
        "fx_question_mark_and_regex": ("athena",),
        "fx_cidr_mixed_families": ("athena",),
        "fx_negated_group_underscore": ("cloudwatch", "athena"),
    }
    for name, targets in want.items():
        conv = fixture(name)
        got = tuple(t for t in ("cloudwatch", "athena") if t in conv)
        assert got == targets, (name, got, conv.get("cloudwatch_skipped"), conv.get("athena_skipped"))


FIXTURE_EXPECTATIONS = {
    "fx_all_modifier_and_contains": [
        ({"userAgent": "aws-cli/2 Linux/5", "eventName": "PutBucketPolicy"}, True),
        ({"userAgent": "aws-cli/2 Darwin", "eventName": "PutBucketPolicy"}, False),      # |all: both needed
        ({"userAgent": "Linux boto3", "eventName": "PutBucketPolicy"}, False),
        ({"userAgent": "aws-cli/2 Linux/5", "eventName": "ListBuckets"}, False)],
    "fx_all_of_them_and_cased": [
        ({"eventSource": "iam.amazonaws.com", "eventName": "CreateUser"}, True),          # _ignored excluded
        ({"eventSource": "iam.amazonaws.com", "eventName": "createuser"}, False),         # |cased
        ({"eventSource": "IAM.amazonaws.com", "eventName": "CreateUser"}, True, False)],  # not cased; CloudWatch is
    "fx_nested_logic_ints_null": [
        ({"eventName": "RunInstances", "errorCode": "AccessDenied"}, True),
        ({"eventName": "RunInstances"}, False),                                           # errorCode null
        ({"eventName": "Other", "requestParameters.maxCount": 5, "errorCode": "X"}, True),
        ({"eventName": "Other", "requestParameters.maxCount": 6, "errorCode": "X"}, False),
        ({"eventName": "RunInstances", "errorCode": "X", "userIdentity.type": "Root"}, False)],
    "fx_exists_and_escape": [
        ({"requestParameters.note": "it's *literal"}, True),
        ({"requestParameters.note": "it's Xliteral"}, False),                             # \* is not a wildcard
        ({"requestParameters.note": "it's *literal",
          "userIdentity.sessionContext": {"sessionIssuer": {"userName": "role"}}}, False)],
    "fx_negated_group_underscore": [
        ({"eventSource": "iam.amazonaws.com", "userAgent": "boto3_cli/1", "eventName": "ListUsers"}, True),
        ({"eventSource": "iam.amazonaws.com", "userAgent": "boto3Acli/1", "eventName": "ListUsers"}, False),
        ({"eventSource": "iam.amazonaws.com", "userAgent": "boto3_cli/1", "eventName": "CreateUser"}, False),
        ({"eventSource": "iam.amazonaws.com", "userAgent": "boto3_cli/1", "eventName": "ListUsers",
          "userIdentity.type": "Root"}, False)],
    "fx_question_mark_and_regex": [
        ({"eventName": "DeleteTrail"}, True), ({"eventName": "DeleteXrail"}, True),
        ({"eventName": "DeleteTTrail"}, False), ({"eventName": "STOPLOGGING"}, True),
        ({"eventName": "StopLoggingNow"}, False),
        ({"errorMessage": "what?"}, True), ({"errorMessage": "whatX"}, False)],         # \\? is a literal ?
}


def test_fixture_rules_hand_written_expectations():
    """Parser-level semantics. Differential testing cannot see parser bugs (all three
    implementations share the parsed rule), so these are written out by hand."""
    for name, cases in FIXTURE_EXPECTATIONS.items():
        check_expectations(fixture(name), cases)


def test_cloudwatch_case_sensitivity_is_the_only_divergence():
    conv = lab_rules()["sigma_organizations_leave"]
    ev = base_event()
    set_path(ev, "eventSource", "organizations.amazonaws.com")
    set_path(ev, "eventName", "leaveorganization")                   # wrong case
    ref, ath, cw = evaluate(conv, [ev])
    assert ref == [True] and ath == [True] and cw == [False], (ref, ath, cw)


# --- Unsupported constructs are reported, never mistranslated -------------------------------------

def test_unsupported_constructs_are_reported_with_reasons():
    cases = {
        "keywords": ("detection: {kw: [evil, bad], condition: kw}", "keyword"),
        "aggregation": ("detection: {sel: {eventName: X}, condition: 'sel | count() > 5'}", "aggregation"),
        "unknown_modifier": ("detection: {sel: {eventName|base64: X}, condition: sel}", "modifier"),
        "other_logsource": (None, "logsource"),
        "unknown_identifier": ("detection: {sel: {eventName: X}, condition: sel and nope}", "unknown identifier"),
        "unbalanced": ("detection: {sel: {eventName: X}, condition: '(sel'}", "parentheses"),
    }
    for name, (det, reason) in cases.items():
        body = f"title: {name}\nlogsource: {{product: aws, service: cloudtrail}}\n{det}\n" if det else \
               f"title: {name}\nlogsource: {{product: windows, category: process_creation}}\ndetection: {{sel: {{Image: x}}, condition: sel}}\n"
        conv = convert_text(body, f"{name}.yml")
        assert reason in conv.get("error", ""), (name, conv)

    target_cases = {
        "array_field": ("detection: {sel: {resources.ARN: 'arn:*'}, condition: sel}", "inside an array", "inside an array"),
        "mid_wildcard": ("detection: {sel: {eventName: 'Delete*Trail'}, condition: sel}", "start or end", None),
        "unknown_athena_field": ("detection: {sel: {userIdentity.nope: x}, condition: sel}", None, "no such field"),
        "template_syntax": ("detection: {sel: {userAgent: 'a${b}'}, condition: sel}", None, "template syntax"),
        "not_null": ("detection: {sel: {errorCode: null}, condition: not sel}", "cannot test that a field exists", None),
    }
    # Logs Insights: arrays are refused; RE2 has no lookaround or backreferences.
    conv = convert_text("title: arr\nlogsource: {product: aws, service: cloudtrail}\n"
                        "detection: {sel: {resources.ARN: 'arn:*'}, condition: sel}\n", "arr.yml")
    assert "inside an array" in conv.get("insights_skipped", ""), conv
    conv = convert_text("title: look\nlogsource: {product: aws, service: cloudtrail}\n"
                        "detection: {sel: {eventName|re: '^Delete(?!Trail)'}, condition: sel}\n", "look.yml")
    assert "RE2" in conv.get("insights_skipped", "") and "athena" in conv, conv
    for name, (det, cw_reason, ath_reason) in target_cases.items():
        conv = convert_text(f"title: {name}\nlogsource: {{product: aws, service: cloudtrail}}\n{det}\n", f"{name}.yml")
        assert "error" not in conv, (name, conv.get("error"))
        if cw_reason:
            assert cw_reason in conv.get("cloudwatch_skipped", ""), (name, conv)
        else:
            assert "cloudwatch" in conv, (name, conv)
        if ath_reason:
            assert ath_reason in conv.get("athena_skipped", ""), (name, conv)
        else:
            assert "athena" in conv, (name, conv)

    long_list = "[" + ", ".join(f"VeryLongEventNameNumber{i:03d}" for i in range(60)) + "]"
    conv = convert_text("title: long\nlogsource: {product: aws, service: cloudtrail}\n"
                        f"detection: {{sel: {{eventName: {long_list}}}, condition: sel}}\n", "long.yml")
    assert "CloudWatch allows 1024" in conv.get("cloudwatch_skipped", "") and "athena" in conv, conv


# --- Generated files, schema and Terraform contract ------------------------------------------------------

def test_generated_files_are_current():
    assert sc.main(["--check"]) == 0, "run scripts/sigma_convert.py and commit sigma/generated/"


def test_converter_field_map_matches_the_glue_table():
    schema = dict(th.module_schema())
    for col in list(sc.TOP_LEVEL.values()) + list(sc.JSON_COLUMNS.values()):
        assert schema.get(col) == "string", f"{col} is not a string column of the CloudTrail table"

    def paths(node, prefix):
        for k, v in node.items():
            p = f"{prefix}.{k}"
            yield from (paths(v, p) if isinstance(v, dict) else [p])

    for head, tree in sc.STRUCTS.items():
        struct_type = schema[head.lower()]
        for p in paths(tree, head):
            fields = [seg.lower() for seg in p.split(".")[1:]]
            t = struct_type
            for f in fields:
                m = re.search(rf"(?:<|,){f}:", t)
                assert m, f"{p} not in Glue type of {head.lower()}"
                t = t[m.end():]


def test_metric_filters_json_fits_the_detection_catalogue():
    data = json.loads((ROOT / "sigma" / "generated" / "metric_filters.json").read_text())
    for name, d in data.items():
        assert set(d) == {"source", "description", "attack", "threshold", "pattern"}, name
        assert name.startswith("sigma_") and d["source"] == "cloudtrail" and len(d["pattern"]) <= 1024
        cwl_parse(d["pattern"])
    hunts = sorted(p.stem for p in (ROOT / "sigma" / "generated" / "hunts").glob("*.sql"))
    assert hunts == sorted(r["slug"] for r in sc.convert_all() if "athena" in r)
    for h in hunts:
        sql = (ROOT / "sigma" / "generated" / "hunts" / f"{h}.sql").read_text()
        rendered = th._fill(sql, {"database": th.DB, "table": th.TABLE, "lookback_days": 30, "ip_key": th.ip_key()})
        sqlglot.parse_one(rendered, read="athena", error_level=sqlglot.ErrorLevel.RAISE)
        for key in ("title", "attack", "purpose", "requires", "schedule-time-column"):
            assert re.search(rf"(?m)^-- {key}:", sql), (h, key)


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {name}\n{traceback.format_exc()[-2500:]}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
