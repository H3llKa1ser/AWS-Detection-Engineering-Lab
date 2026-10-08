#!/usr/bin/env python3
"""
Import abuse.ch Feodo Tracker's botnet C2 IP blocklist (recommended) into
intel/indicators/feodotracker.csv in the lab's curated format.

The feed is a snapshot: the output file is replaced, so IPs that left the feed
leave the file. Imported rows expire after --days (default 30), because C2
infrastructure is short-lived and cloud IPs get reassigned to innocent tenants.
Review the git diff before committing, and respect the feed's terms of use
(https://feodotracker.abuse.ch/blocklist/).

    python3 scripts/import_feodo.py                  # fetch and write
    python3 scripts/import_feodo.py --input saved.txt --days 14
"""
import argparse
import csv
import datetime as dt
import ipaddress
import pathlib
import sys
import urllib.request

URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
OUT = pathlib.Path(__file__).resolve().parents[1] / "intel" / "indicators" / "feodotracker.csv"
COLUMNS = ["indicator", "type", "source", "confidence", "added", "expires", "description", "reference"]
INTERNAL = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4")]


def parse_feed(text):
    """Return (ips, skipped). Comments and blanks are ignored; anything that is
    not a public IPv4 address is skipped with a reason, never imported."""
    ips, skipped = [], []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ip = ipaddress.IPv4Address(line)
        except ValueError:
            skipped.append((line, "not an IPv4 address"))
            continue
        if any(ip in n for n in INTERNAL):
            skipped.append((line, "internal or reserved address"))
            continue
        ips.append(str(ip))
    return sorted(set(ips), key=lambda a: ipaddress.IPv4Address(a)), skipped


def build_rows(ips, today, days):
    expires = (today + dt.timedelta(days=days)).isoformat()
    return [{"indicator": ip, "type": "ipv4", "source": "feodotracker", "confidence": "medium",
             "added": today.isoformat(), "expires": expires,
             "description": "Botnet C2 server listed by abuse.ch Feodo Tracker (recommended blocklist)",
             "reference": URL} for ip in ips]


def write_csv(rows, path):
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--input", help="read a saved copy of the feed instead of downloading")
    ap.add_argument("--days", type=int, default=30, help="days until imported indicators expire (default 30)")
    ap.add_argument("--output", default=str(OUT))
    args = ap.parse_args(argv)

    if args.input:
        text = pathlib.Path(args.input).read_text()
    else:
        req = urllib.request.Request(URL, headers={"User-Agent": "aws-detection-lab-intel-import"})
        text = urllib.request.urlopen(req, timeout=30).read().decode()

    ips, skipped = parse_feed(text)
    for value, why in skipped:
        print(f"skipped {value!r}: {why}", file=sys.stderr)
    rows = build_rows(ips, dt.date.today(), args.days)
    write_csv(rows, args.output)
    print(f"wrote {len(rows)} indicators to {args.output} (expire in {args.days} days)"
          + ("; the feed was empty, which happens: the file now holds only the header" if not rows else ""))


if __name__ == "__main__":
    main()
