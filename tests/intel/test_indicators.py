#!/usr/bin/env python3
"""
Curation rules for intel/indicators/*.csv, plus a Python mirror of how
Terraform merges them (modules/threat-intel), plus tests for the feed importer.

Run in CI on every change to intel/:

    python3 tests/intel/test_indicators.py

Terraform checks the essentials at plan time; this suite enforces the full
rules (real address parsing, every internal and reserved range, CIDR
alignment, unknown columns, expiry policy).
"""
import csv
import datetime as dt
import importlib.util
import io
import ipaddress
import pathlib
import re
import sys
import tempfile
import traceback

ROOT = pathlib.Path(__file__).resolve().parents[2]
INTEL_DIR = ROOT / "intel" / "indicators"
COLUMNS = ["indicator", "type", "source", "confidence", "added", "expires", "description", "reference"]
REQUIRED = COLUMNS[:-1]
INTERNAL = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4")]
NEVER_DOMAINS = {"amazonaws.com", "amazon.com", "aws.amazon.com", "cloudfront.net", "github.com", "googleapis.com",
                 "google.com", "microsoft.com", "windows.net", "azure.com", "akamaiedge.net", "cloudflare.com"}
INTERNAL6 = [ipaddress.ip_network(n) for n in (
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64",
    "fc00::/7", "fe80::/10", "ff00::/8")]   # 2001:db8::/32 (documentation) is allowed for canaries
DOMAIN_RE = re.compile(r"^([a-z0-9_-]+\.)+[a-z0-9-]+$")
MAX_LIFETIME_DAYS = 400
LONG_LIVED_SOURCES = {"lab-canary"}   # canaries must outlive the lab


def read_dir(directory=INTEL_DIR):
    """Return [(file, header, rows)] with Terraform's normalisation applied."""
    out = []
    for path in sorted(pathlib.Path(directory).glob("*.csv")):
        reader = csv.DictReader(io.StringIO(path.read_text()))
        rows = []
        for r in reader:
            row = {c: (r.get(c) or "").strip() for c in COLUMNS}
            for c in ("indicator", "type", "confidence"):
                row[c] = row[c].lower()
            rows.append(row)
        out.append((path.name, reader.fieldnames or [], rows))
    return out


def validate(files, today=None):
    """Return (errors, warnings) as lists of strings."""
    today = today or dt.date.today()
    errors, warnings, seen = [], [], {}
    for name, header, rows in files:
        missing = [c for c in REQUIRED if c not in header]
        unknown = [c for c in header if c not in COLUMNS]
        if missing:
            errors.append(f"{name}: missing columns {missing}")
        if unknown:
            errors.append(f"{name}: unknown columns {unknown} (typo? expected {COLUMNS})")
        for n, r in enumerate(rows, start=2):
            where = f"{name}:{n} {r['indicator'] or '(empty)'}"
            for c in REQUIRED:
                if not r[c]:
                    errors.append(f"{where}: empty {c}")
            if r["type"] not in ("ipv4", "ipv6", "cidr", "domain"):
                errors.append(f"{where}: type must be ipv4, ipv6, cidr or domain")
            if r["confidence"] not in ("low", "medium", "high"):
                errors.append(f"{where}: confidence must be low, medium or high")
            try:
                added, expires = dt.date.fromisoformat(r["added"]), dt.date.fromisoformat(r["expires"])
                if expires < added:
                    errors.append(f"{where}: expires before added")
                elif (expires - added).days > MAX_LIFETIME_DAYS and r["source"] not in LONG_LIVED_SOURCES:
                    errors.append(f"{where}: lifetime over {MAX_LIFETIME_DAYS} days; re-verify and re-date instead")
                if expires < today:
                    warnings.append(f"{where}: expired {r['expires']} (no longer matches; prune it)")
            except ValueError:
                errors.append(f"{where}: added/expires must be real YYYY-MM-DD dates")
            ind = r["indicator"]
            if r["type"] == "ipv4":
                try:
                    ip = ipaddress.IPv4Address(ind)
                    if any(ip in net for net in INTERNAL):
                        errors.append(f"{where}: internal or reserved address")
                except ValueError:
                    errors.append(f"{where}: not an IPv4 address")
            elif r["type"] == "ipv6":
                try:
                    ip = ipaddress.IPv6Address(ind)
                    if any(ip in net for net in INTERNAL6):
                        errors.append(f"{where}: internal, special or IPv4-embedding IPv6 address (use an ipv4 row for IPv4)")
                    elif ind != ip.compressed:
                        errors.append(f"{where}: not canonical; write it as {ip.compressed} (RFC 5952)")
                except ValueError:
                    errors.append(f"{where}: not an IPv6 address")
            elif r["type"] == "cidr":
                v6 = ":" in ind
                try:
                    net = (ipaddress.IPv6Network if v6 else ipaddress.IPv4Network)(ind, strict=True)
                    if net.prefixlen < (32 if v6 else 16):
                        errors.append(f"{where}: wider than /{32 if v6 else 16}")
                    if any(net.overlaps(i) for i in (INTERNAL6 if v6 else INTERNAL)):
                        errors.append(f"{where}: overlaps an internal or reserved range")
                    elif ind != str(net):
                        errors.append(f"{where}: not canonical; write it as {net}")
                except ValueError as e:
                    errors.append(f"{where}: not an aligned {'IPv6' if v6 else 'IPv4'} CIDR ({e})")
            elif r["type"] == "domain":
                if not DOMAIN_RE.match(ind):
                    errors.append(f"{where}: not a bare domain (no scheme, path, port, wildcard or trailing dot)")
                if ind in NEVER_DOMAINS:
                    errors.append(f"{where}: platform apex domain; would match far too much")
            key = (r["type"], ind)
            if key in seen:
                errors.append(f"{where}: duplicate of {seen[key]}")
            seen.setdefault(key, where)
    return errors, warnings


def merged_csv(directory=INTEL_DIR):
    """Mirror of local.content in modules/threat-intel/main.tf (first row wins per key)."""
    by_key = {}
    for _, _, rows in read_dir(directory):
        for r in rows:
            by_key.setdefault(f"{r['type']}|{r['indicator']}", r)
    lines = [",".join('"%s"' % by_key[k][c].replace('"', '""') for c in COLUMNS) for k in sorted(by_key)]
    return ",".join(COLUMNS) + "\n" + "\n".join(lines) + "\n"


def _files(text, name="t.csv"):
    d = tempfile.mkdtemp()
    (pathlib.Path(d) / name).write_text(text)
    return read_dir(d)


HEADER = ",".join(COLUMNS) + "\n"


# --- Tests ---------------------------------------------------------------------------

def test_curated_files_are_valid():
    errors, warnings = validate(read_dir())
    for w in warnings:
        print(f"  warning: {w}")
    assert not errors, "\n".join(errors)


def test_validator_catches_each_rule():
    cases = {
        "10.1.2.3,ipv4,s,high,2026-10-01,2026-11-01,d,": "internal or reserved",
        "224.0.0.5,ipv4,s,high,2026-10-01,2026-11-01,d,": "internal or reserved",
        "100.64.1.0/24,cidr,s,high,2026-10-01,2026-11-01,d,": "overlaps an internal",
        "8.8.0.0/8,cidr,s,high,2026-10-01,2026-11-01,d,": "not an aligned",
        "8.0.0.0/8,cidr,s,high,2026-10-01,2026-11-01,d,": "wider than /16",
        "cloudfront.net,domain,s,high,2026-10-01,2026-11-01,d,": "platform apex",
        "http://x.example,domain,s,high,2026-10-01,2026-11-01,d,": "not a bare domain",
        "x.example.,domain,s,high,2026-10-01,2026-11-01,d,": "not a bare domain",
        "x.example,domain,s,urgent,2026-10-01,2026-11-01,d,": "confidence must be",
        "x.example,domain,s,high,2026-10-01,2026-02-30,d,": "real YYYY-MM-DD",
        "x.example,domain,s,high,2026-10-01,2026-09-01,d,": "expires before added",
        "x.example,domain,s,high,2026-01-01,2028-01-01,d,": "lifetime over",
        "x.example,domain,s,high,2026-10-01,2026-11-01,,": "empty description",
        "fd00::1,ipv6,s,high,2026-10-01,2026-11-01,d,": "internal, special",
        "fe80::1,ipv6,s,high,2026-10-01,2026-11-01,d,": "internal, special",
        "ff02::1,ipv6,s,high,2026-10-01,2026-11-01,d,": "internal, special",
        "::1,ipv6,s,high,2026-10-01,2026-11-01,d,": "internal, special",
        "::ffff:192.0.2.1,ipv6,s,high,2026-10-01,2026-11-01,d,": "IPv4-embedding",
        "2001:db8:0::1,ipv6,s,high,2026-10-01,2026-11-01,d,": "not canonical; write it as 2001:db8::1",
        "2001:db8::/16,cidr,s,high,2026-10-01,2026-11-01,d,": "not an aligned IPv6",
        "2001::/16,cidr,s,high,2026-10-01,2026-11-01,d,": "wider than /32",
        "2001:db8::1/32,cidr,s,high,2026-10-01,2026-11-01,d,": "not an aligned IPv6",
        "fc00::/8,cidr,s,high,2026-10-01,2026-11-01,d,": "overlaps an internal",
        "2001:db8:0:0::/48,cidr,s,high,2026-10-01,2026-11-01,d,": "not canonical; write it as 2001:db8::/48",
        "2001:db8::1,ipv4,s,high,2026-10-01,2026-11-01,d,": "not an IPv4 address",
        "192.0.2.1,ipv6,s,high,2026-10-01,2026-11-01,d,": "not an IPv6 address",
    }
    # And valid IPv6 rows pass cleanly.
    # Case is normalised (as Terraform does), so upper case is fine; compression form is not.
    ok, _ = validate(_files(HEADER + "2001:DB8::1,ipv6,s,high,2026-10-01,2026-11-01,d,\n"
                                     "2001:db8:abcd::/48,cidr,s,high,2026-10-01,2026-11-01,d,\n"), today=dt.date(2026, 10, 8))
    assert ok == [], ok
    for row, expected in cases.items():
        errors, _ = validate(_files(HEADER + row + "\n"), today=dt.date(2026, 10, 8))
        assert any(expected in e for e in errors), (row, expected, errors)


def test_validator_flags_unknown_columns_and_duplicates():
    errors, _ = validate(_files("indicator,type,source,confidence,added,expiry,description\n"
                                "x.example,domain,s,high,2026-10-01,2026-11-01,d\n"))
    assert any("unknown columns ['expiry']" in e for e in errors) and any("missing columns" in e for e in errors), errors
    d = tempfile.mkdtemp()
    for n in ("a.csv", "b.csv"):
        (pathlib.Path(d) / n).write_text(HEADER + "X.Example,domain,s,high,2026-10-01,2026-11-01,d,\n")
    errors, _ = validate(read_dir(d), today=dt.date(2026, 10, 8))
    assert any("duplicate of a.csv" in e for e in errors), errors          # case-insensitive


def test_expired_rows_warn_but_do_not_fail():
    errors, warnings = validate(_files(HEADER + "x.example,domain,s,high,2026-01-01,2026-02-01,d,\n"),
                                today=dt.date(2026, 10, 8))
    assert not errors and any("expired" in w for w in warnings), (errors, warnings)


def test_merge_is_sorted_quoted_and_order_independent():
    a = HEADER + 'b.example,domain,s,high,2026-10-01,2026-11-01,"says ""hi"", twice",\n'
    b = HEADER + "a.example,domain,s,high,2026-10-01,2026-11-01,d,\n"
    d1, d2 = tempfile.mkdtemp(), tempfile.mkdtemp()
    (pathlib.Path(d1) / "1.csv").write_text(a + b[len(HEADER):])
    (pathlib.Path(d2) / "1.csv").write_text(b + a[len(HEADER):])
    m1, m2 = merged_csv(d1), merged_csv(d2)
    assert m1 == m2, "row order in a file must not change the uploaded object"
    parsed = list(csv.DictReader(io.StringIO(m1)))
    assert [r["indicator"] for r in parsed] == ["a.example", "b.example"], parsed
    assert parsed[1]["description"] == 'says "hi", twice', parsed


def _importer():
    spec = importlib.util.spec_from_file_location("imp", ROOT / "scripts" / "import_feodo.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


FEED = """################################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (recommended)  #
################################################################
#
# DstIP
203.0.113.7
198.51.100.23
2001:DB8:0::bad
fe80::1

10.0.0.5
not-an-ip
203.0.113.7
# END 4 entries
"""


def test_importer_parses_feed_safely():
    imp = _importer()
    ips, skipped = imp.parse_feed(FEED)
    assert ips == ["198.51.100.23", "203.0.113.7", "2001:db8::bad"], ips      # deduplicated, sorted, IPv6 canonical
    assert dict(skipped) == {"10.0.0.5": "internal or reserved address", "fe80::1": "internal or reserved address",
                             "not-an-ip": "not an IP address"}, skipped
    assert imp.parse_feed("# header only\n# END 0 entries\n") == ([], [])      # empty feed is not an error


def test_importer_output_passes_curation_rules():
    imp = _importer()
    d = tempfile.mkdtemp()
    out = pathlib.Path(d) / "feodotracker.csv"
    imp.main(["--input", str(_write(FEED)), "--days", "14", "--output", str(out)])
    errors, _ = validate(read_dir(d))
    assert not errors, errors
    rows = list(csv.DictReader(out.open()))
    assert [(r["indicator"], r["type"]) for r in rows] == [("198.51.100.23", "ipv4"), ("203.0.113.7", "ipv4"),
                                                           ("2001:db8::bad", "ipv6")], rows
    assert (dt.date.fromisoformat(rows[0]["expires"]) - dt.date.fromisoformat(rows[0]["added"])).days == 14


def _write(text):
    p = pathlib.Path(tempfile.mkdtemp()) / "feed.txt"
    p.write_text(text)
    return p


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
