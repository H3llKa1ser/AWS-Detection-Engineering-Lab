"""
Opt-in auto-response for GuardDuty findings.

Triggered by EventBridge on GuardDuty findings of type
Recon:EC2/PortProbeUnprotectedPort. It revokes the offending security-group
ingress rule and publishes a note to the alert topic. Conservative by design:
it only ever *removes* over-permissive access, never grants it, and it no-ops
on any finding type it does not understand.
"""
import json
import os

import boto3

ec2 = boto3.client("ec2")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["ALERT_TOPIC_ARN"]


def _notify(message: str) -> None:
    sns.publish(TopicArn=TOPIC_ARN, Subject="Auto-response executed", Message=message)


def handler(event, _context):
    detail = event.get("detail", {})
    finding_type = detail.get("type", "")

    if not finding_type.startswith("Recon:EC2/PortProbeUnprotectedPort"):
        print(f"Ignoring finding type: {finding_type}")
        return {"status": "ignored", "type": finding_type}

    service = detail.get("service", {})
    remote = service.get("action", {}).get("portProbeAction", {})
    probe_details = remote.get("portProbeDetails", [])

    instance = detail.get("resource", {}).get("instanceDetails", {})
    sg_ids = sorted({
        sg["groupId"]
        for eni in instance.get("networkInterfaces", [])
        for sg in eni.get("securityGroups", [])
    })

    revoked = []
    for sg_id in sg_ids:
        for probe in probe_details:
            port = probe.get("localPortDetails", {}).get("port")
            if port is None:
                continue
            try:
                resp = ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[{
                        "IpProtocol": "tcp",
                        "FromPort": port,
                        "ToPort": port,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }],
                )
                # EC2 can return success while listing the rule as unknown,
                # i.e. nothing matched and nothing was removed.
                if resp.get("UnknownIpPermissions"):
                    print(f"No matching 0.0.0.0/0 rule for {sg_id}:{port}")
                else:
                    revoked.append(f"{sg_id}:{port}")
            except ec2.exceptions.ClientError as exc:
                print(f"No matching rule for {sg_id}:{port} ({exc})")

    msg = (
        f"GuardDuty {finding_type}\n"
        f"Revoked 0.0.0.0/0 ingress rules: {revoked or 'none matched'}"
    )
    _notify(msg)
    print(msg)
    return {"status": "done", "revoked": revoked}
