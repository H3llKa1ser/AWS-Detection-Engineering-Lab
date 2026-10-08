-- title: IAM persistence (credentials, users, admin grants, trust changes)
-- attack: T1098.001 Additional Cloud Credentials / T1136.003 Create Account: Cloud Account / T1098.003 Additional Cloud Roles
-- purpose: Successful IAM changes used to keep access, ranked so keys or passwords created for someone else and AdministratorAccess grants come first.
WITH changes AS (
  SELECT
    from_iso8601_timestamp(eventtime) AS ts,
    eventname,
    coalesce(useridentity.arn, useridentity.principalid) AS actor,
    useridentity.username AS actor_username,
    json_extract_scalar(requestparameters, '$.userName') AS target_user,
    json_extract_scalar(requestparameters, '$.roleName') AS target_role,
    json_extract_scalar(requestparameters, '$.policyArn') AS policy_arn,
    sourceipaddress,
    useragent
  FROM "${database}"."${table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND eventsource = 'iam.amazonaws.com'
    AND errorcode IS NULL
    AND eventname IN (
      'CreateUser', 'CreateAccessKey', 'CreateLoginProfile', 'UpdateLoginProfile',
      'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy',
      'PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy', 'AddUserToGroup',
      'CreateRole', 'UpdateAssumeRolePolicy', 'DeactivateMFADevice', 'DeleteVirtualMFADevice'
    )
)
SELECT
  CASE
    WHEN eventname IN ('CreateAccessKey', 'CreateLoginProfile', 'UpdateLoginProfile')
         AND target_user IS NOT NULL
         AND target_user <> coalesce(actor_username, '')
      THEN '1 credential created for ANOTHER identity'
    WHEN policy_arn LIKE '%:policy/AdministratorAccess' THEN '2 AdministratorAccess granted'
    WHEN eventname = 'UpdateAssumeRolePolicy' THEN '3 role trust policy changed'
    WHEN eventname IN ('DeactivateMFADevice', 'DeleteVirtualMFADevice') THEN '4 MFA removed'
    ELSE '5 review'
  END AS finding,
  ts, eventname, actor, target_user, target_role, policy_arn, sourceipaddress, useragent
FROM changes
ORDER BY finding, ts DESC
LIMIT 500
