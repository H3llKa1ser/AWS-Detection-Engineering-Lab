#!/usr/bin/env python3
"""
Sandbox janitor: finds what crashed or cancelled e2e runs left behind.

  stale-states   print the name prefixes of e2e runs whose Terraform state is
                 still in the state bucket after --older-than-hours (a run
                 that finished cleanly deletes its state); the workflow then
                 runs `terraform destroy` for each and deletes the state.
  sweep          delete test activity that lives outside Terraform state:
                 e2e alert queues and e2e target IAM users older than the
                 threshold.

    python3 tests/live/janitor.py stale-states --bucket <state bucket>
    python3 tests/live/janitor.py sweep
"""
import argparse
import re
import sys
from datetime import datetime, timedelta, timezone

import boto3

STATE_KEY = re.compile(r"^e2e/(e2e-[0-9]+-[0-9]+)/terraform\.tfstate$")
PREFIX = re.compile(r"^e2e-[0-9]+-[0-9]+$")


def stale_prefixes(objects, cutoff):
    """objects: [{'Key', 'LastModified'}] -> sorted prefixes with state older than cutoff."""
    out = []
    for obj in objects:
        m = STATE_KEY.match(obj["Key"])
        if m and obj["LastModified"] < cutoff:
            out.append(m.group(1))
    return sorted(set(out))


def stale_states(s3, bucket, cutoff):
    objects = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="e2e/"):
        objects += page.get("Contents", [])
    return stale_prefixes(objects, cutoff)


def sweep(session, cutoff, dry_run=False):
    removed = []
    sqs = session.client("sqs")
    for url in sqs.list_queues(QueueNamePrefix="e2e-").get("QueueUrls", []):
        name = url.rsplit("/", 1)[1]
        if not (name.endswith("-e2e-alerts") and PREFIX.match(name[: -len("-e2e-alerts")])):
            continue
        created = int(sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["CreatedTimestamp"])
                      ["Attributes"]["CreatedTimestamp"])
        if datetime.fromtimestamp(created, timezone.utc) < cutoff:
            removed.append(f"queue {name}")
            if not dry_run:
                sqs.delete_queue(QueueUrl=url)
    iam = session.client("iam")
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            if not (name.endswith("-target") and PREFIX.match(name[: -len("-target")])):
                continue
            if user["CreateDate"] < cutoff:
                removed.append(f"iam user {name}")
                if not dry_run:
                    for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                        iam.delete_access_key(UserName=name, AccessKeyId=key["AccessKeyId"])
                    iam.delete_user(UserName=name)
    return removed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["stale-states", "sweep"])
    ap.add_argument("--bucket")
    ap.add_argument("--older-than-hours", type=float, default=6)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=args.older_than_hours)
    session = boto3.Session()
    if args.mode == "stale-states":
        if not args.bucket:
            sys.exit("--bucket is required")
        print("\n".join(stale_states(session.client("s3"), args.bucket, cutoff)))
    else:
        for r in sweep(session, cutoff, args.dry_run):
            print(("would remove " if args.dry_run else "removed ") + r)


if __name__ == "__main__":
    main()
