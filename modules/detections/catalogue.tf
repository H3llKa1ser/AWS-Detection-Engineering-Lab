# ---------------------------------------------------------------------------
# Detection catalogue (detection-as-code)
#
# Each entry becomes a CloudWatch Logs metric filter + alarm evaluated against
# the CloudTrail log group. Filters follow the CIS AWS Foundations Benchmark
# monitoring controls and are annotated with the MITRE ATT&CK technique they
# map to, so the catalogue doubles as living documentation.
#
# To add a detection: add a map entry. Nothing else to touch.
# ---------------------------------------------------------------------------

locals {
  detections = {
    unauthorized_api_calls = {
      description = "Unauthorized / access-denied API calls (CIS 3.1)"
      attack      = "TA0007 Discovery / T1078 Valid Accounts"
      pattern     = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
    }
    console_signin_no_mfa = {
      description = "Console sign-in without MFA (CIS 3.2)"
      attack      = "T1078 Valid Accounts"
      pattern     = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type = \"IAMUser\") && ($.responseElements.ConsoleLogin = \"Success\") }"
    }
    root_account_usage = {
      description = "Use of the root account (CIS 3.3)"
      attack      = "T1078.004 Valid Accounts: Cloud Accounts"
      pattern     = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
    }
    iam_policy_changes = {
      description = "IAM policy changes (CIS 3.4)"
      attack      = "T1098 Account Manipulation"
      pattern     = "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) }"
    }
    cloudtrail_config_changes = {
      description = "CloudTrail configuration changes (CIS 3.5)"
      attack      = "T1562.008 Impair Defenses: Disable Cloud Logs"
      pattern     = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
    }
    console_auth_failures = {
      description = "Failed console authentication (CIS 3.6)"
      attack      = "T1110 Brute Force"
      pattern     = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
    }
    cmk_disable_or_delete = {
      description = "Disabling or scheduled deletion of a KMS CMK (CIS 3.7)"
      attack      = "T1485 Data Destruction / T1486 Data Encrypted for Impact"
      pattern     = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
    }
    s3_policy_changes = {
      description = "S3 bucket policy / ACL changes (CIS 3.8)"
      attack      = "T1530 Data from Cloud Storage Object"
      pattern     = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
    }
    config_changes = {
      description = "AWS Config service changes (CIS 3.9)"
      attack      = "T1562.008 Impair Defenses: Disable Cloud Logs"
      pattern     = "{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }"
    }
    security_group_changes = {
      description = "Security group changes (CIS 3.10)"
      attack      = "T1562.007 Impair Defenses: Disable or Modify Cloud Firewall"
      pattern     = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
    }
    nacl_changes = {
      description = "Network ACL changes (CIS 3.11)"
      attack      = "T1562.007 Impair Defenses: Disable or Modify Cloud Firewall"
      pattern     = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
    }
    network_gateway_changes = {
      description = "Network gateway changes (CIS 3.12)"
      attack      = "T1562.007 Impair Defenses: Disable or Modify Cloud Firewall"
      pattern     = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
    }
    route_table_changes = {
      description = "Route table changes (CIS 3.13)"
      attack      = "T1562.007 Impair Defenses: Disable or Modify Cloud Firewall"
      pattern     = "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
    }
    vpc_changes = {
      description = "VPC changes (CIS 3.14)"
      attack      = "T1562.007 Impair Defenses: Disable or Modify Cloud Firewall"
      pattern     = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) }"
    }
    organizations_changes = {
      description = "AWS Organizations changes (CIS 3.15)"
      attack      = "T1098 Account Manipulation"
      pattern     = "{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = AcceptHandshake) || ($.eventName = AttachPolicy) || ($.eventName = CreateAccount) || ($.eventName = CreateOrganizationalUnit) || ($.eventName = CreatePolicy) || ($.eventName = DeclineHandshake) || ($.eventName = DeleteOrganization) || ($.eventName = DeleteOrganizationalUnit) || ($.eventName = DeletePolicy) || ($.eventName = DetachPolicy) || ($.eventName = DisablePolicyType) || ($.eventName = EnablePolicyType) || ($.eventName = InviteAccountToOrganization) || ($.eventName = LeaveOrganization) || ($.eventName = MoveAccount) || ($.eventName = RemoveAccountFromOrganization) || ($.eventName = UpdatePolicy) || ($.eventName = UpdateOrganizationalUnit)) }"
    }
  }
}
