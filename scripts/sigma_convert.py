#!/usr/bin/env python3
"""
Convert Sigma rules for AWS CloudTrail into this lab's two detection targets:

  * CloudWatch Logs metric filters (real-time alarms, merged into the
    detection catalogue), and
  * Athena hunts (saved queries over the CloudTrail table, schedulable like
    every other hunt).

A rule is converted to each target only where the target can express it with
the same meaning; otherwise that target is skipped and the reason recorded in
sigma/generated/REPORT.md. Nothing is converted approximately.

    python3 scripts/sigma_convert.py            # regenerate sigma/generated/
    python3 scripts/sigma_convert.py --check    # CI: fail if generated files are stale

Supported Sigma subset (logsource product aws, service cloudtrail):
  condition   and / or / not, parentheses, "1 of x*", "all of x*", "1 of them",
              "all of them" (no aggregations or correlations)
  values      strings with * and ? wildcards (backslash escapes), integers,
              booleans, null; lists (any, or every with |all)
  modifiers   contains, startswith, endswith, all, re (+ i), cidr, cased, exists

Semantics follow the Sigma specification: string matching is case-insensitive
unless |cased, and a condition on an absent field is false (so "not" of it is
true). CloudWatch metric filters are case-sensitive and cannot test that a
field exists; see REPORT.md and docs/architecture.md for exactly what that
means for each rule.
"""
import argparse
import ipaddress
import json
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "sigma" / "rules"
OUT_DIR = ROOT / "sigma" / "generated"
CWL_MAX_PATTERN = 1024


class Unsupported(Exception):
    """The rule (or one target) cannot be converted faithfully."""


# --- Intermediate representation ----------------------------------------------------
# Expressions are tuples:
#   ("and", [exprs]) | ("or", [exprs]) | ("not", expr)
#   ("match", field, kind, value, cased)
#     kind "pattern": value = list of tokens ("lit", text) | ("star",) | ("q",)
#     kind "int" / "bool": value = int / bool
#     kind "null": value = None          (absent or null)
#     kind "exists": value = bool        (present and not null)
#     kind "re": value = (regex, flags)
#     kind "cidr": value = ipaddress network

def parse_sigma_string(text):
    """Sigma string -> tokens. * and ? are wildcards; backslash escapes them."""
    tokens, buf, i = [], "", 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text) and text[i + 1] in "*?\\":
            buf += text[i + 1]
            i += 2
            continue
        if c in "*?":
            if buf:
                tokens.append(("lit", buf))
                buf = ""
            tokens.append(("star",) if c == "*" else ("q",))
        else:
            buf += c
        i += 1
    if buf:
        tokens.append(("lit", buf))
    return tokens


SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "i", "cidr", "cased", "exists"}


def leaf(field, modifiers, value):
    cased = "cased" in modifiers
    if "exists" in modifiers:
        if not isinstance(value, bool):
            raise Unsupported(f"{field}|exists needs true or false")
        return ("match", field, "exists", value, cased)
    if "re" in modifiers:
        if not isinstance(value, str):
            raise Unsupported(f"{field}|re needs a string")
        return ("match", field, "re", (value, "i" if "i" in modifiers else ""), True)
    if "cidr" in modifiers:
        try:
            return ("match", field, "cidr", ipaddress.ip_network(str(value), strict=False), True)
        except ValueError as e:
            raise Unsupported(f"{field}|cidr: {e}")
    if value is None:
        return ("match", field, "null", None, cased)
    if isinstance(value, bool):
        return ("match", field, "bool", value, cased)
    if isinstance(value, int):
        if modifiers & {"contains", "startswith", "endswith"}:
            value = str(value)
        else:
            return ("match", field, "int", value, cased)
    if not isinstance(value, str):
        raise Unsupported(f"{field}: unsupported value type {type(value).__name__}")
    tokens = parse_sigma_string(value)
    if "contains" in modifiers:
        tokens = [("star",)] + tokens + [("star",)]
    elif "startswith" in modifiers:
        tokens = tokens + [("star",)]
    elif "endswith" in modifiers:
        tokens = [("star",)] + tokens
    return ("match", field, "pattern", tokens, cased)


def parse_field_key(key):
    field, *mods = key.split("|")
    mods = set(mods)
    unknown = mods - SUPPORTED_MODIFIERS
    if unknown:
        raise Unsupported(f"modifier(s) not supported: {', '.join(sorted(unknown))}")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*", field):
        raise Unsupported(f"field name not supported: {field!r}")
    return field, mods


def parse_search_identifier(body):
    if isinstance(body, list):
        if not body:
            raise Unsupported("empty list in detection")
        if all(isinstance(b, dict) for b in body):
            return ("or", [parse_search_identifier(b) for b in body])
        raise Unsupported("keyword (field-less) searches are not supported")
    if not isinstance(body, dict) or not body:
        raise Unsupported("detection items must be non-empty maps")
    parts = []
    for key, value in body.items():
        field, mods = parse_field_key(key)
        values = value if isinstance(value, list) else [value]
        if not values:
            raise Unsupported(f"{field}: empty value list")
        leaves = [leaf(field, mods, v) for v in values]
        parts.append(leaves[0] if len(leaves) == 1 else ("and" if "all" in mods else "or", leaves))
    return parts[0] if len(parts) == 1 else ("and", parts)


def tokenize_condition(cond):
    if "|" in cond:
        raise Unsupported("aggregation conditions (|) are not supported")
    return re.findall(r"\(|\)|[^\s()]+", cond)


def parse_condition(cond, items):
    if isinstance(cond, list):
        return ("or", [parse_condition(c, items) for c in cond])
    toks = tokenize_condition(cond)
    pos = 0

    def peek():
        return toks[pos].lower() if pos < len(toks) else None

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def resolve(pattern):
        if pattern == "them":
            names = [n for n in items if not n.startswith("_")]
        else:
            rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
            names = [n for n in items if rx.match(n)]
        if not names:
            raise Unsupported(f"condition refers to nothing: {pattern}")
        return [items[n] for n in sorted(names)]

    def primary():
        t = peek()
        if t is None:
            raise Unsupported("unexpected end of condition")
        if t == "(":
            take()
            e = expr()
            if peek() != ")":
                raise Unsupported("unbalanced parentheses in condition")
            take()
            return e
        if t == "not":
            take()
            return ("not", primary())
        if t in ("1", "all") and pos + 1 < len(toks) and toks[pos + 1].lower() == "of":
            quant = take().lower()
            take()
            exprs = resolve(take())
            return exprs[0] if len(exprs) == 1 else ("or" if quant == "1" else "and", exprs)
        name = take()
        if name not in items:
            raise Unsupported(f"unknown identifier in condition: {name}")
        return items[name]

    def conj():
        parts = [primary()]
        while peek() == "and":
            take()
            parts.append(primary())
        return parts[0] if len(parts) == 1 else ("and", parts)

    def expr():
        parts = [conj()]
        while peek() == "or":
            take()
            parts.append(conj())
        return parts[0] if len(parts) == 1 else ("or", parts)

    result = expr()
    if pos != len(toks):
        raise Unsupported(f"could not parse condition near {toks[pos]!r}")
    return result


def parse_rule(rule):
    ls = rule.get("logsource") or {}
    if (ls.get("product"), ls.get("service")) != ("aws", "cloudtrail"):
        raise Unsupported("logsource must be product: aws, service: cloudtrail")
    det = dict(rule.get("detection") or {})
    cond = det.pop("condition", None)
    if cond is None:
        raise Unsupported("detection has no condition")
    det.pop("timeframe", None)
    items = {name: parse_search_identifier(body) for name, body in det.items()}
    return parse_condition(cond, items)


# --- CloudTrail schema for the Athena table (checked against the Glue table by tests) --
TOP_LEVEL = {
    "eventVersion": "eventversion", "eventTime": "eventtime", "eventSource": "eventsource",
    "eventName": "eventname", "awsRegion": "awsregion", "sourceIPAddress": "sourceipaddress",
    "userAgent": "useragent", "errorCode": "errorcode", "errorMessage": "errormessage",
    "requestID": "requestid", "eventID": "eventid", "eventType": "eventtype", "apiVersion": "apiversion",
    "readOnly": "readonly", "recipientAccountId": "recipientaccountid", "sharedEventID": "sharedeventid",
    "vpcEndpointId": "vpcendpointid", "vpcEndpointAccountId": "vpcendpointaccountid",
    "eventCategory": "eventcategory", "sessionCredentialFromConsole": "sessioncredentialfromconsole",
    "edgeDeviceDetails": "edgedevicedetails",
}
JSON_COLUMNS = {"requestParameters": "requestparameters", "responseElements": "responseelements",
                "additionalEventData": "additionaleventdata", "serviceEventDetails": "serviceeventdetails"}
STRUCTS = {
    "userIdentity": {"type": None, "principalId": None, "arn": None, "accountId": None, "invokedBy": None,
                     "accessKeyId": None, "userName": None,
                     "onBehalfOf": {"userId": None, "identityStoreArn": None},
                     "sessionContext": {"attributes": {"mfaAuthenticated": None, "creationDate": None},
                                        "sessionIssuer": {"type": None, "principalId": None, "arn": None,
                                                          "accountId": None, "userName": None},
                                        "ec2RoleDelivery": None,
                                        "webIdFederationData": {"federatedProvider": None}}},
    "addendum": {"reason": None, "updatedFields": None, "originalRequestId": None, "originalEventId": None},
    "tlsDetails": {"tlsVersion": None, "cipherSuite": None, "clientProvidedHostHeader": None},
}


ARRAY_FIELDS = {"resources"}   # arrays: a Sigma field cannot say which element


def athena_field(field):
    head, *rest = field.split(".")
    if head in ARRAY_FIELDS:
        raise Unsupported(f"{field} is inside an array; Sigma cannot say which element")
    if head in TOP_LEVEL and not rest:
        return TOP_LEVEL[head]
    if head in JSON_COLUMNS and rest:
        return f"json_extract_scalar({JSON_COLUMNS[head]}, '$.{'.'.join(rest)}')"
    if head in STRUCTS and rest:
        node, path = STRUCTS[head], [head.lower()]
        for seg in rest:
            if not isinstance(node, dict) or seg not in node:
                raise Unsupported(f"no such field in the CloudTrail table: {field}")
            node = node[seg]
            path.append(seg.lower())
        if node is not None:
            raise Unsupported(f"{field} is an object, not a value")
        return ".".join(path)
    raise Unsupported(f"field not available in the Athena table: {field}")


def sql_str(s):
    if "${" in s or "%{" in s:
        raise Unsupported("values containing ${ or %{ are not supported (template syntax)")
    return "'" + s.replace("'", "''") + "'"


def ip_hex(ip):
    if ip.version == 4:
        ip = ipaddress.IPv6Address("::ffff:" + str(ip))
    return ip.exploded.replace(":", "")


def athena_expr(e):
    op = e[0]
    if op in ("and", "or"):
        return "(" + f" {op.upper()} ".join(athena_expr(x) for x in e[1]) + ")"
    if op == "not":
        return f"(NOT {athena_expr(e[1])})"
    _, field, kind, value, cased = e
    col = athena_field(field)
    if kind == "null":
        return f"({col} IS NULL)"
    if kind == "exists":
        return f"({col} IS {'NOT ' if value else ''}NULL)"
    if kind == "bool":
        return f"({col} IS NOT NULL AND lower({col}) = '{str(value).lower()}')"
    if kind == "int":
        return f"({col} IS NOT NULL AND {col} = '{value}')"
    if kind == "re":
        rx, flags = value
        return f"({col} IS NOT NULL AND regexp_like({col}, {sql_str(('(?i)' if 'i' in flags else '') + rx)}))"
    if kind == "cidr":
        # A non-IP value has no key, so BETWEEN would be NULL and survive negation as
        # NULL (silently dropping the event). Every leaf must be TRUE or FALSE.
        key = '${replace(ip_key, "IP_IN", "' + col + '")}'
        return (f"coalesce({key} BETWEEN '{ip_hex(value.network_address)}' "
                f"AND '{ip_hex(value.broadcast_address)}', FALSE)")
    # pattern
    tokens = value if cased else [("lit", t[1].lower()) if t[0] == "lit" else t for t in value]
    subject = col if cased else f"lower({col})"
    if all(t[0] == "lit" for t in tokens):
        return f"({col} IS NOT NULL AND {subject} = {sql_str(''.join(t[1] for t in tokens))})"
    like = "".join({"star": "%", "q": "_"}.get(t[0]) or
                   t[1].replace("!", "!!").replace("%", "!%").replace("_", "!_") for t in tokens)
    return f"({col} IS NOT NULL AND {subject} LIKE {sql_str(like)} ESCAPE '!')"


# --- CloudWatch Logs metric filter backend --------------------------------------------
def cwl_selector(field):
    if field.split(".")[0] in ARRAY_FIELDS:
        raise Unsupported(f"{field} is inside an array (a CloudWatch selector on an array never matches)")
    if not re.fullmatch(r"[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*", field):
        raise Unsupported(f"field not expressible as a CloudWatch selector: {field}")
    return "$." + field


def cwl_value(tokens):
    if any(t[0] == "q" for t in tokens):
        raise Unsupported("CloudWatch has no single-character (?) wildcard")
    stars = [i for i, t in enumerate(tokens) if t[0] == "star"]
    if any(0 < i < len(tokens) - 1 for i in stars) or len(stars) > 2:
        raise Unsupported("CloudWatch wildcards only at the start or end of a value")
    text = "".join("*" if t[0] == "star" else t[1] for t in tokens)
    literal = "".join(t[1] for t in tokens if t[0] == "lit")
    if any(c in literal for c in '"\\*'):
        raise Unsupported('values containing ", \\ or a literal * cannot be expressed in CloudWatch')
    return '"' + text + '"'


def nnf(e, neg=False):
    """Push negation down to the leaves (De Morgan)."""
    op = e[0]
    if op == "not":
        return nnf(e[1], not neg)
    if op in ("and", "or"):
        flip = {"and": "or", "or": "and"}[op] if neg else op
        return (flip, [nnf(x, neg) for x in e[1]])
    return ("neg", e) if neg else e


def cwl_expr(e):
    op = e[0]
    if op in ("and", "or"):
        return "(" + (" && " if op == "and" else " || ").join(cwl_expr(x) for x in e[1]) + ")"
    negated = op == "neg"
    _, field, kind, value, cased = e[1] if negated else e
    sel = cwl_selector(field)
    absent = f"{sel} NOT EXISTS || {sel} IS NULL"
    if kind in ("re", "cidr"):
        raise Unsupported(f"|{kind} is not converted for CloudWatch")
    if kind == "null" or (kind == "exists" and value is False):
        if negated:
            raise Unsupported("CloudWatch cannot test that a field exists (EXISTS / IS NOT are unsupported)")
        return f"({absent})"
    if kind == "exists":   # exists: true
        if not negated:
            raise Unsupported("CloudWatch cannot test that a field exists (EXISTS / IS NOT are unsupported)")
        return f"({absent})"
    if kind == "bool":
        if negated:
            return f"({sel} IS {'FALSE' if value else 'TRUE'} || {absent})"
        return f"({sel} IS {'TRUE' if value else 'FALSE'})"
    rhs = str(value) if kind == "int" else cwl_value(value)
    if negated:
        # Sigma: "not x = v" is true when x is absent or null. Spelling that out makes
        # the result independent of how CloudWatch treats != on a missing field.
        return f"({sel} != {rhs} || {absent})"
    return f"({sel} = {rhs})"


def to_cloudwatch(ir):
    body = cwl_expr(nnf(ir))
    pattern = "{ " + body + " }"
    if len(pattern) > CWL_MAX_PATTERN:
        raise Unsupported(f"pattern is {len(pattern)} characters; CloudWatch allows {CWL_MAX_PATTERN}")
    return pattern


def case_sensitive_caveat(ir):
    """True if the rule compares letters case-insensitively, which CloudWatch cannot."""
    def walk(e):
        if e[0] in ("and", "or"):
            return any(walk(x) for x in e[1])
        if e[0] in ("not", "neg"):
            return walk(e[1])
        _, _, kind, value, cased = e
        return kind == "pattern" and not cased and any(t[0] == "lit" and t[1].lower() != t[1].upper() for t in value)
    return walk(ir)


# --- Rule-level conversion and outputs -------------------------------------------------
def slug_for(path):
    return "sigma_" + re.sub(r"[^a-z0-9]+", "_", path.stem.lower()).strip("_")


def attack_of(rule):
    tags = [t.lower() for t in rule.get("tags") or []]
    techniques = sorted({t.split(".", 1)[1].upper() for t in tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)})
    return " / ".join(techniques) if techniques else "(no ATT&CK technique tag)"


def one_line(text):
    return " ".join(str(text or "").split())


HUNT_TEMPLATE = """-- title: Sigma: {title}
-- attack: {attack}
-- purpose: {description} (Sigma rule {id}, level {level}, status {status})
-- requires: cloudtrail
-- schedule-time-column: ts
-- schedule-baseline: false
-- generated-from: {source}. Do not edit: change the rule and run scripts/sigma_convert.py.
-- falsepositives: {falsepositives}
SELECT
  from_iso8601_timestamp(eventtime) AS ts,
  eventsource, eventname, errorcode, awsregion, sourceipaddress, useragent,
  coalesce(useridentity.arn, useridentity.principalid) AS identity,
  requestparameters
FROM "${{database}}"."${{table}}"
WHERE dt >= date_format(current_date - interval '${{lookback_days}}' day, '%Y/%m/%d')
  AND {condition}
ORDER BY ts DESC
LIMIT 500
"""


def convert_rule(path):
    """Return a dict describing one rule's conversion (never raises for rule content)."""
    try:
        rel = path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        rel = path.name
    try:
        rule = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        return {"file": rel, "slug": slug_for(path), "title": path.name, "error": f"invalid YAML: {e}"}
    out = {"file": rel, "slug": slug_for(path), "title": one_line(rule.get("title")), "id": rule.get("id", ""),
           "level": rule.get("level", ""), "status": rule.get("status", ""), "attack": attack_of(rule)}
    try:
        ir = parse_rule(rule)
    except Unsupported as e:
        out["error"] = str(e)
        return out
    for target, fn in (("cloudwatch", to_cloudwatch), ("athena", athena_expr)):
        try:
            out[target] = fn(ir)
        except Unsupported as e:
            out[f"{target}_skipped"] = str(e)
    out["case_caveat"] = "cloudwatch" in out and case_sensitive_caveat(ir)
    if "athena" in out:
        out["hunt_sql"] = HUNT_TEMPLATE.format(
            title=out["title"], attack=out["attack"], id=out["id"] or "(no id)", level=out["level"] or "-",
            status=out["status"] or "-", description=one_line(rule.get("description")) or out["title"],
            source=rel, falsepositives=one_line("; ".join(map(str, rule.get("falsepositives") or ["none listed"]))),
            condition=out["athena"])
    out["ir"] = ir
    return out


def render_outputs(results):
    files = {}
    filters = {r["slug"]: {"source": "cloudtrail", "description": f"Sigma: {r['title']} ({r['level'] or 'no level'})",
                           "attack": r["attack"], "threshold": 1, "pattern": r["cloudwatch"]}
               for r in results if "cloudwatch" in r}
    files["metric_filters.json"] = json.dumps(filters, indent=2, sort_keys=True) + "\n"
    for r in results:
        if "hunt_sql" in r:
            files[f"hunts/{r['slug']}.sql"] = r["hunt_sql"]

    def cell(text):
        return str(text).replace("|", "\\|")

    caveat = sum(r.get("case_caveat", False) for r in results)
    lines = ["# Sigma conversion report", "",
             "Generated by `scripts/sigma_convert.py`. Do not edit.", "",
             "Each rule is converted to a target only if the target can express it with the same meaning; "
             "otherwise the reason is listed. Athena hunts follow Sigma semantics exactly (case-insensitive "
             "unless `|cased`). CloudWatch metric filters are case-sensitive: "
             f"{caveat} CloudWatch conversion(s) compare letters case-insensitively in Sigma and therefore assume "
             "CloudTrail's own casing (exact for service-generated fields such as eventSource and eventName).", "",
             f"{len(results)} rules: {sum('cloudwatch' in r for r in results)} converted to CloudWatch metric filters, "
             f"{sum('athena' in r for r in results)} to Athena hunts, {sum('error' in r for r in results)} not converted.", "",
             "| Rule | Level | ATT&CK | CloudWatch metric filter | Athena hunt |",
             "|------|-------|--------|--------------------------|-------------|"]
    for r in results:
        if "error" in r:
            lines.append(f"| `{r['file']}` | {r.get('level', '')} | {r.get('attack', '')} "
                         f"| not converted: {cell(r['error'])} | not converted |")
            continue
        cw = f"yes (`{r['slug']}`)" if "cloudwatch" in r else f"no: {cell(r['cloudwatch_skipped'])}"
        at = f"yes (`{r['slug']}`)" if "athena" in r else f"no: {cell(r['athena_skipped'])}"
        lines.append(f"| {cell(r['title'])} (`{r['file']}`) | {r['level']} | {r['attack']} | {cw} | {at} |")
    files["REPORT.md"] = "\n".join(lines) + "\n"
    return files


def convert_all(rules_dir=RULES_DIR):
    return [convert_rule(p) for p in sorted(pathlib.Path(rules_dir).rglob("*.yml"))]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="exit 1 if sigma/generated/ is out of date")
    ap.add_argument("--rules", default=str(RULES_DIR))
    ap.add_argument("--out", default=str(OUT_DIR))
    args = ap.parse_args(argv)

    results = convert_all(args.rules)
    slugs = [r["slug"] for r in results]
    if len(set(slugs)) != len(slugs):
        sys.exit(f"duplicate rule file names (slugs): {sorted(s for s in slugs if slugs.count(s) > 1)}")
    files = render_outputs(results)
    out = pathlib.Path(args.out)
    existing = {p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()} if out.exists() else set()

    if args.check:
        stale = [f for f, c in files.items() if not (out / f).exists() or (out / f).read_text() != c]
        extra = sorted(existing - set(files))
        if stale or extra:
            print("sigma/generated/ is out of date; run scripts/sigma_convert.py", file=sys.stderr)
            for f in stale + extra:
                print(f"  {f}", file=sys.stderr)
            return 1
        print(f"sigma/generated/ is up to date ({len(results)} rules)")
        return 0

    for f in existing - set(files):
        (out / f).unlink()
    for f, content in files.items():
        (out / f).parent.mkdir(parents=True, exist_ok=True)
        (out / f).write_text(content)
    for r in results:
        status = "error: " + r["error"] if "error" in r else ", ".join(
            t for t in ("cloudwatch", "athena") if t in r) or "nothing"
        print(f"{r['slug']:55} {status}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
