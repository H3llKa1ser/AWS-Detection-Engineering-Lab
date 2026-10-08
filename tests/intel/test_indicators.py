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
            if r["type"] not in ("ipv4", "cidr", "domain"):
                errors.append(f"{where}: type must be ipv4, cidr or domain")
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
            elif r["type"] == "cidr":
                try:
                    net = ipaddress.IPv4Network(ind, strict=True)
                    if net.prefixlen < 16:
                        errors.append(f"{where}: wider than /16")
                    if any(net.overlaps(i) for i in INTERNAL):
                        errors.append(f"{where}: overlaps an internal or reserved range")
                except ValueError as e:
                    errors.append(f"{where}: not an aligned IPv4 CIDR ({e})")
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
    }
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

10.0.0.5
not-an-ip
203.0.113.7
# END 4 entries
"""


def test_importer_parses_feed_safely():
    imp = _importer()
    ips, skipped = imp.parse_feed(FEED)
    assert ips == ["198.51.100.23", "203.0.113.7"], ips                       # deduplicated, sorted numerically
    assert dict(skipped) == {"10.0.0.5": "internal or reserved address", "not-an-ip": "not an IPv4 address"}, skipped
    assert imp.parse_feed("# header only\n# END 0 entries\n") == ([], [])      # empty feed is not an error


def test_importer_output_passes_curation_rules():
    imp = _importer()
    d = tempfile.mkdtemp()
    out = pathlib.Path(d) / "feodotracker.csv"
    imp.main(["--input", str(_write(FEED)), "--days", "14", "--output", str(out)])
    errors, _ = validate(read_dir(d))
    assert not errors, errors
    rows = list(csv.DictReader(out.open()))
    assert len(rows) == 2 and all(r["source"] == "feodotracker" and r["type"] == "ipv4" for r in rows), rows
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
