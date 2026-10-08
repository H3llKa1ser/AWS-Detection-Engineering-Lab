"""
Sample log events for every built-in metric-filter detection
(modules/detections/catalogue*.tf), with the expected match.

Used live (tests/live/test_conformance.py) against the real CloudWatch Logs
TestMetricFilter API, and offline (tests/live/test_harness_offline.py) against
the CloudWatch model for the JSON patterns. Cases whose expectation rests on
behaviour the CloudWatch documentation does not state are marked "PROBE": if
the service disagrees, the model (and docs) must be corrected.
"""
import json

FLOW_FIELDS = ["version", "account_id", "interface_id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol",
               "packets", "bytes", "start", "end", "action", "log_status", "vpc_id", "subnet_id", "instance_id",
               "tcp_flags", "type", "pkt_srcaddr", "pkt_dstaddr", "flow_direction"]


def ct(**fields):
    base = {"eventVersion": "1.09", "eventTime": "2026-10-08T10:00:00Z", "awsRegion": "eu-west-1",
            "sourceIPAddress": "198.51.100.7", "userAgent": "aws-cli/2", "eventType": "AwsApiCall",
            "userIdentity": {"type": "IAMUser", "userName": "alice", "arn": "arn:aws:iam::111122223333:user/alice"},
            "recipientAccountId": "111122223333"}
    for k, v in fields.items():
        node, parts = base, k.split(".")
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        if v is None and parts[-1] in node:
            del node[parts[-1]]
        elif v is not None:
            node[parts[-1]] = v
    return json.dumps(base, separators=(",", ":"))


def flow(**fields):
    rec = {"version": "5", "account_id": "111122223333", "interface_id": "eni-0abc", "srcaddr": "10.42.1.10",
           "dstaddr": "198.51.100.7", "srcport": "51515", "dstport": "443", "protocol": "6", "packets": "10",
           "bytes": "4000", "start": "1760000000", "end": "1760000060", "action": "ACCEPT", "log_status": "OK",
           "vpc_id": "vpc-0abc", "subnet_id": "subnet-0abc", "instance_id": "i-0abc", "tcp_flags": "2",
           "type": "IPv4", "pkt_srcaddr": "10.42.1.10", "pkt_dstaddr": "198.51.100.7", "flow_direction": "egress"}
    rec.update({k: str(v) for k, v in fields.items()})
    return " ".join(rec[f] for f in FLOW_FIELDS)


def dns(**fields):
    rec = {"version": "1.100000", "account_id": "111122223333", "region": "eu-west-1", "vpc_id": "vpc-0abc",
           "query_timestamp": "2026-10-08T10:00:00Z", "query_name": "example.com.", "query_type": "A",
           "query_class": "IN", "rcode": "NOERROR", "answers": [], "srcaddr": "10.42.1.10", "srcport": "53000",
           "transport": "UDP", "srcids": {"instance": "i-0abc"}}
    rec.update(fields)
    return json.dumps(rec, separators=(",", ":"))


SAMPLES = {
    "unauthorized_api_calls": [
        (ct(errorCode="Client.UnauthorizedOperation"), True, "leading wildcard"),
        (ct(errorCode="AccessDeniedException"), True, "trailing wildcard"),
        (ct(errorCode="ThrottlingException"), False, ""),
        (ct(), False, "no errorCode")],
    "console_signin_no_mfa": [
        (ct(eventName="ConsoleLogin", **{"additionalEventData.MFAUsed": "No", "responseElements.ConsoleLogin": "Success"}), True, ""),
        (ct(eventName="ConsoleLogin", **{"additionalEventData.MFAUsed": "Yes", "responseElements.ConsoleLogin": "Success"}), False, ""),
        (ct(eventName="ConsoleLogin", **{"responseElements.ConsoleLogin": "Success"}), False,
         "PROBE: != on a missing field (MFAUsed absent); model assumes no match")],
    "root_account_usage": [
        (ct(eventName="ListBuckets", **{"userIdentity": {"type": "Root"}}), True, ""),
        (ct(eventName="ListBuckets", **{"userIdentity": {"type": "Root", "invokedBy": "support.amazonaws.com"}}), False, ""),
        (ct(eventName="Health", eventType="AwsServiceEvent", **{"userIdentity": {"type": "Root"}}), False, "")],
    "iam_policy_changes": [
        (ct(eventName="AttachUserPolicy"), True, "unquoted value"), (ct(eventName="ListPolicies"), False, "")],
    "cloudtrail_config_changes": [
        (ct(eventName="StopLogging"), True, "unquoted value"), (ct(eventName="LookupEvents"), False, "")],
    "console_auth_failures": [
        (ct(eventName="ConsoleLogin", errorMessage="Failed authentication"), True, "quoted phrase"),
        (ct(eventName="ConsoleLogin"), False, "")],
    "cmk_disable_or_delete": [
        (ct(eventSource="kms.amazonaws.com", eventName="ScheduleKeyDeletion"), True,
         "PROBE: unquoted value containing dots (kms.amazonaws.com)"),
        (ct(eventSource="kms.amazonaws.com", eventName="Decrypt"), False, ""),
        (ct(eventSource="kmsXamazonaws.com", eventName="DisableKey"), False, "PROBE: dots are literal, not wildcards")],
    "s3_policy_changes": [
        (ct(eventSource="s3.amazonaws.com", eventName="PutBucketPolicy"), True, "unquoted value with dots"),
        (ct(eventSource="s3.amazonaws.com", eventName="GetBucketPolicy"), False, "")],
    "config_changes": [
        (ct(eventSource="config.amazonaws.com", eventName="StopConfigurationRecorder"), True, ""),
        (ct(eventSource="config.amazonaws.com", eventName="DescribeConfigRules"), False, "")],
    "security_group_changes": [
        (ct(eventName="AuthorizeSecurityGroupIngress"), True, ""), (ct(eventName="DescribeSecurityGroups"), False, "")],
    "nacl_changes": [(ct(eventName="CreateNetworkAclEntry"), True, ""), (ct(eventName="DescribeNetworkAcls"), False, "")],
    "network_gateway_changes": [(ct(eventName="AttachInternetGateway"), True, ""), (ct(eventName="DescribeInternetGateways"), False, "")],
    "route_table_changes": [(ct(eventName="CreateRoute"), True, ""), (ct(eventName="DescribeRouteTables"), False, "")],
    "vpc_changes": [(ct(eventName="ModifyVpcAttribute"), True, ""), (ct(eventName="DescribeVpcs"), False, "")],
    "organizations_changes": [
        (ct(eventSource="organizations.amazonaws.com", eventName="LeaveOrganization"), True, ""),
        (ct(eventSource="organizations.amazonaws.com", eventName="ListAccounts"), False, "")],

    "flow_ssh_rejected_ingress": [
        (flow(action="REJECT", dstport=22, flow_direction="ingress", srcaddr="203.0.113.9", dstaddr="10.42.1.10"), True, ""),
        (flow(action="ACCEPT", dstport=22, flow_direction="ingress"), False, ""),
        (flow(action="REJECT", dstport=2222, flow_direction="ingress"), False, "PROBE: quoted \"22\" is exact, not prefix")],
    "flow_rdp_rejected_ingress": [
        (flow(action="REJECT", dstport=3389, flow_direction="ingress"), True, ""),
        (flow(action="REJECT", dstport=3389, flow_direction="egress"), False, "")],
    "flow_reject_spike": [(flow(action="REJECT"), True, ""), (flow(action="ACCEPT"), False, "")],
    "flow_egress_smb_accepted": [
        (flow(action="ACCEPT", dstport=445, flow_direction="egress"), True, ""),
        (flow(action="ACCEPT", dstport=445, flow_direction="ingress"), False, "")],
    "flow_large_egress_transfer": [
        (flow(action="ACCEPT", bytes=600000000, flow_direction="egress"), True, "numeric comparison"),
        (flow(action="ACCEPT", bytes=400000000, flow_direction="egress"), False, "")],

    "dns_nxdomain_spike": [(dns(rcode="NXDOMAIN"), True, ""), (dns(rcode="NOERROR"), False, "")],
    "dns_txt_query_spike": [(dns(query_type="TXT"), True, ""), (dns(query_type="AAAA"), False, "")],
    "dns_mining_pool_lookup": [
        (dns(query_name="xmr.nanopool.org."), True, "leading wildcard"),
        (dns(query_name="nanopool.org."), False, "apex has no leading label: *. requires a dot"),
        (dns(query_name="xmr.nanopool.org.evil."), False, "")],
    "dns_onion_lookup": [(dns(query_name="abc.onion."), True, ""), (dns(query_name="onion.example."), False, "")],
    "dns_firewall_block": [(dns(firewall_rule_action="BLOCK"), True, ""), (dns(firewall_rule_action="ALERT"), False, ""),
                           (dns(), False, "")],
    "dns_firewall_alert": [(dns(firewall_rule_action="ALERT"), True, ""), (dns(firewall_rule_action="BLOCK"), False, "")],
}
