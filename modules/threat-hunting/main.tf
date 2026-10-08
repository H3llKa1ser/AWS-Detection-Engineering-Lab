# ---------------------------------------------------------------------------
# Threat hunting over CloudTrail with Athena
#
#   Glue database + table   CloudTrail JSON in S3, read in place (no copies,
#                           no crawler). Partition projection on region and
#                           day, so new days are queryable immediately and
#                           every hunt prunes to the dates it asks for.
#   Athena workgroup        Engine v3, encrypted results in a dedicated
#                           bucket, settings enforced, per-query scan cap.
#   Saved hunts             queries/*.sql rendered with this deployment's
#                           names and saved as named queries in the workgroup.
#   Hunter IAM policy       Least privilege to run hunts; CloudTrail read-only,
#                           so hunting can never alter the evidence.
# ---------------------------------------------------------------------------

data "aws_regions" "enabled" {}

locals {
  # Athena identifiers: lowercase, underscores only.
  database = "${replace(lower(var.name_prefix), "-", "_")}_security"
  table    = "cloudtrail"

  cloudtrail_prefix = "AWSLogs/${var.account_id}/CloudTrail"
  results_bucket    = "${var.name_prefix}-athena-results-${var.account_id}-${var.region}"

  # Column types from AWS's Athena CloudTrail DDL (JsonSerDe variant, which
  # handles newer CloudTrail fields that the legacy CloudTrailSerde does not).
  # Written multi-line for readability; whitespace is stripped for Glue.
  t = { for k, v in {
    useridentity = <<-T
      struct<type:string,principalid:string,arn:string,accountid:string,
      invokedby:string,accesskeyid:string,username:string,
      onbehalfof:struct<userid:string,identitystorearn:string>,
      sessioncontext:struct<
        attributes:struct<mfaauthenticated:string,creationdate:string>,
        sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>,
        ec2roledelivery:string,
        webidfederationdata:struct<federatedprovider:string,attributes:map<string,string>>>>
    T
    resources    = "array<struct<arn:string,accountid:string,type:string>>"
    addendum     = "struct<reason:string,updatedfields:string,originalrequestid:string,originaleventid:string>"
    tlsdetails   = "struct<tlsversion:string,ciphersuite:string,clientprovidedhostheader:string>"
  } : k => replace(v, "/\\s+/", "") }

  columns = [
    ["eventversion", "string"], ["useridentity", local.t.useridentity], ["eventtime", "string"],
    ["eventsource", "string"], ["eventname", "string"], ["awsregion", "string"],
    ["sourceipaddress", "string"], ["useragent", "string"], ["errorcode", "string"],
    ["errormessage", "string"], ["requestparameters", "string"], ["responseelements", "string"],
    ["additionaleventdata", "string"], ["requestid", "string"], ["eventid", "string"],
    ["resources", local.t.resources], ["eventtype", "string"], ["apiversion", "string"],
    ["readonly", "string"], ["recipientaccountid", "string"], ["serviceeventdetails", "string"],
    ["sharedeventid", "string"], ["vpcendpointid", "string"], ["vpcendpointaccountid", "string"],
    ["eventcategory", "string"], ["addendum", local.t.addendum],
    ["sessioncredentialfromconsole", "string"], ["edgedevicedetails", "string"],
    ["tlsdetails", local.t.tlsdetails],
  ]
}

# --- Catalog ----------------------------------------------------------------
resource "aws_glue_catalog_database" "security" {
  name        = local.database
  description = "Security telemetry for threat hunting (${var.name_prefix})"
}

resource "aws_glue_catalog_table" "cloudtrail" {
  name          = local.table
  database_name = aws_glue_catalog_database.security.name
  description   = "CloudTrail management events, read in place from s3://${var.cloudtrail_bucket_name}/${local.cloudtrail_prefix}/"
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL       = "TRUE"
    classification = "cloudtrail"

    # Partition projection: Athena computes partitions from these rules
    # instead of a crawler or ALTER TABLE ADD PARTITION.
    "projection.enabled"          = "true"
    "projection.region.type"      = "enum"
    "projection.region.values"    = join(",", sort(tolist(data.aws_regions.enabled.names)))
    "projection.dt.type"          = "date"
    "projection.dt.format"        = "yyyy/MM/dd"
    "projection.dt.range"         = "${var.projection_start},NOW"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "DAYS"
    "storage.location.template"   = "s3://${var.cloudtrail_bucket_name}/${local.cloudtrail_prefix}/$${region}/$${dt}"
  }

  partition_keys {
    name    = "region"
    type    = "string"
    comment = "CloudTrail delivery region folder (global-service events land in us-east-1)"
  }
  partition_keys {
    name    = "dt"
    type    = "string"
    comment = "Delivery day, yyyy/MM/dd. Always filter on it: it is what keeps scans cheap."
  }

  storage_descriptor {
    location      = "s3://${var.cloudtrail_bucket_name}/${local.cloudtrail_prefix}/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hive.hcatalog.data.JsonSerDe"
    }

    dynamic "columns" {
      for_each = local.columns
      content {
        name = columns.value[0]
        type = columns.value[1]
      }
    }
  }
}

# --- Query results bucket ------------------------------------------------------
# Results can contain sensitive extracts of CloudTrail (IPs, principals,
# request parameters), so they get the same protection as the logs.
resource "aws_s3_bucket" "results" {
  bucket        = local.results_bucket
  force_destroy = true # lab convenience
}

resource "aws_s3_bucket_public_access_block" "results" {
  bucket                  = aws_s3_bucket.results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "results" {
  bucket = aws_s3_bucket.results.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "results" {
  bucket = aws_s3_bucket.results.id
  rule {
    id     = "expire-query-results"
    status = "Enabled"
    filter {}
    expiration { days = var.results_retention_days }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

data "aws_iam_policy_document" "results_tls" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.results.arn, "${aws_s3_bucket.results.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "results" {
  bucket = aws_s3_bucket.results.id
  policy = data.aws_iam_policy_document.results_tls.json
}

# --- Workgroup ----------------------------------------------------------------------
resource "aws_athena_workgroup" "hunting" {
  name          = "${var.name_prefix}-threat-hunting"
  description   = "CloudTrail threat hunting. Settings enforced; scans capped per query."
  force_destroy = true # deletes saved queries with the workgroup (lab)

  configuration {
    enforce_workgroup_configuration    = true # clients cannot redirect or unencrypt results
    publish_cloudwatch_metrics_enabled = true
    bytes_scanned_cutoff_per_query     = var.bytes_scanned_cutoff

    engine_version {
      selected_engine_version = "Athena engine version 3"
    }

    result_configuration {
      output_location       = "s3://${aws_s3_bucket.results.bucket}/results/"
      expected_bucket_owner = var.account_id

      encryption_configuration {
        encryption_option = var.kms_key_arn == null ? "SSE_S3" : "SSE_KMS"
        kms_key_arn       = var.kms_key_arn
      }
    }
  }
}

# --- Saved hunts ------------------------------------------------------------------
# Each queries/*.sql file has a header the module parses:
#   -- title: ...      (named-query name)
#   -- attack: ...     (MITRE ATT&CK mapping)
#   -- purpose: ...    (one-line description)
locals {
  # Hand-written hunts plus any extra directories (generated Sigma hunts).
  query_paths = merge(
    { for f in fileset("${path.module}/queries", "*.sql") : trimsuffix(f, ".sql") => "${path.module}/queries/${f}" },
    merge([for d in var.extra_query_dirs : { for f in fileset(d, "*.sql") : trimsuffix(f, ".sql") => "${d}/${f}" }]...),
  )

  # Shared SQL (modules/threat-hunting/sql/), tested in tests/hunts/test_ip_keys.py:
  #   ip_key        canonical 32-hex key for any IPv4/IPv6 text (placeholder IP_IN)
  #   cidr_ranges   CTE chain turning cidr_text into [lo, hi] key ranges
  #   internal_nets private/special ranges plus internal_cidrs, as ranges
  #   intel_active  unexpired indicators: IP ranges plus domains
  ip_key = trimspace(file("${path.module}/sql/ip_key.sql"))

  internal_nets = trimspace(templatefile("${path.module}/sql/internal_nets.sql.tftpl", {
    extra_rows = join("", [for c in var.internal_cidrs : ", ('${lower(c)}')"])
    ranges = trimspace(templatefile("${path.module}/sql/cidr_ranges.sql.tftpl", {
      src = "internal_cidrs", dst = "internal_nets", ip_key = local.ip_key
    }))
  }))

  intel_active = trimspace(templatefile("${path.module}/sql/intel_active.sql.tftpl", {
    database    = local.database
    intel_table = var.intel_table
    ranges = trimspace(templatefile("${path.module}/sql/cidr_ranges.sql.tftpl", {
      src = "intel_raw", dst = "intel_ranged", ip_key = local.ip_key
    }))
  }))

  queries = { for k, qp in local.query_paths : k => {
    sql = templatefile(qp, {
      database      = local.database
      table         = local.table
      flow_table    = var.flow_table
      dns_table     = var.dns_table
      intel_table   = var.intel_table
      intel_active  = local.intel_active
      internal_nets = local.internal_nets
      ip_key        = local.ip_key
      lookback_days = var.lookback_days
      recent_days   = var.recent_days
    })
    requires = split(",", replace(try(regex("(?m)^-- requires:(.*)$", file(qp))[0], "cloudtrail"), " ", ""))
    raw      = file(qp)
    title    = trimspace(regex("(?m)^-- title:(.*)$", file(qp))[0])
    attack   = trimspace(regex("(?m)^-- attack:(.*)$", file(qp))[0])
    purpose  = trimspace(regex("(?m)^-- purpose:(.*)$", file(qp))[0])

    # Optional scheduling metadata; absent means "not schedulable" (e.g. pivots).
    time_column = try(trimspace(regex("(?m)^-- schedule-time-column:(.*)$", file(qp))[0]), null)
    baseline    = try(trimspace(regex("(?m)^-- schedule-baseline:(.*)$", file(qp))[0]) == "true", false)
  } }

  # Only hunts whose tables exist are saved or schedulable.
  deployable  = { for k, q in local.queries : k => q if length(setsubtract(q.requires, var.available_sources)) == 0 }
  schedulable = { for k, q in local.deployable : k => q if q.time_column != null }

  # Scheduled variants. Baseline hunts keep the full lookback (they need history
  # to know what is new) with a 2-day "recent" span; the rest only need the last
  # 2 days of partitions, which keeps daily scans small. The wrapper then keeps
  # rows from the 24h window ending schedule_lag_hours before the run.
  scheduled = { for k in var.scheduled_hunts : k => {
    title  = lookup(local.queries, k, { title = k }).title
    attack = lookup(local.queries, k, { attack = "" }).attack
    sql = contains(keys(local.schedulable), k) ? templatefile("${path.module}/scheduled_wrapper.sql.tftpl", {
      name        = k
      time_column = local.schedulable[k].time_column
      start_hours = 24 + var.schedule_lag_hours
      end_hours   = var.schedule_lag_hours
      inner = trimspace(templatefile(local.query_paths[k], {
        database      = local.database
        table         = local.table
        flow_table    = var.flow_table
        dns_table     = var.dns_table
        intel_table   = var.intel_table
        intel_active  = local.intel_active
        internal_nets = local.internal_nets
        ip_key        = local.ip_key
        internal_nets = local.internal_nets
        ip_key        = local.ip_key
        lookback_days = local.schedulable[k].baseline ? var.lookback_days : 2
        recent_days   = 2
      }))
    }) : ""
  } }
}

resource "aws_athena_named_query" "hunt" {
  for_each = local.deployable

  name        = substr("${each.key}: ${each.value.title}", 0, 128)
  workgroup   = aws_athena_workgroup.hunting.name
  database    = aws_glue_catalog_database.security.name
  description = substr("${each.value.purpose} | ATT&CK: ${each.value.attack}", 0, 1024)
  query       = each.value.sql

  depends_on = [aws_glue_catalog_table.cloudtrail]
}

# Retro-hunt variants of the intel hunts: full lookback, plus findings_total so
# the scheduled-hunts state machine can report them like any other run.
locals {
  retro = { for k, q in local.schedulable : k => {
    title  = q.title
    attack = q.attack
    sql = templatefile("${path.module}/retro_wrapper.sql.tftpl", {
      name  = k
      inner = trimspace(q.sql)
    })
  } if contains(q.requires, "intel") }
}

resource "aws_athena_named_query" "retro" {
  for_each = local.retro

  name        = substr("retro/${each.key}: ${each.value.title}", 0, 128)
  workgroup   = aws_athena_workgroup.hunting.name
  database    = aws_glue_catalog_database.security.name
  description = substr("Retro-hunt variant: full lookback, run when the indicator set changes. | ATT&CK: ${each.value.attack}", 0, 1024)
  query       = each.value.sql

  depends_on = [aws_glue_catalog_table.cloudtrail]
}

resource "aws_athena_named_query" "scheduled" {
  for_each = local.scheduled

  name        = substr("scheduled/${each.key}: ${each.value.title}", 0, 128)
  workgroup   = aws_athena_workgroup.hunting.name
  database    = aws_glue_catalog_database.security.name
  description = substr("Scheduled daily variant: findings from the 24h window ending ${var.schedule_lag_hours}h before each run. | ATT&CK: ${each.value.attack}", 0, 1024)
  query       = each.value.sql

  lifecycle {
    precondition {
      condition     = contains(keys(local.schedulable), each.key)
      error_message = "Hunt '${each.key}' cannot be scheduled: it does not exist, declares no schedule-time-column, or needs a table that is not deployed (network log lake). Schedulable: ${join(", ", sort(keys(local.schedulable)))}."
    }
  }

  depends_on = [aws_glue_catalog_table.cloudtrail]
}

# --- Hunter permissions -----------------------------------------------------------
# Attach to the users/roles who hunt. Read-only on CloudTrail by design.
data "aws_iam_policy_document" "hunter" {
  statement {
    sid    = "RunQueriesInHuntingWorkgroup"
    effect = "Allow"
    actions = [
      "athena:StartQueryExecution", "athena:StopQueryExecution",
      "athena:GetQueryExecution", "athena:GetQueryResults", "athena:GetQueryResultsStream",
      "athena:ListQueryExecutions", "athena:BatchGetQueryExecution",
      "athena:GetWorkGroup", "athena:ListNamedQueries", "athena:GetNamedQuery",
      "athena:BatchGetNamedQuery",
    ]
    resources = [aws_athena_workgroup.hunting.arn]
  }

  statement {
    sid       = "ReadDefaultDataCatalog"
    effect    = "Allow"
    actions   = ["athena:GetDataCatalog"]
    resources = ["arn:${var.partition}:athena:${var.region}:${var.account_id}:datacatalog/AwsDataCatalog"]
  }

  statement {
    sid       = "ListWorkgroupsAndCatalogs"
    effect    = "Allow"
    actions   = ["athena:ListWorkGroups", "athena:ListDataCatalogs", "athena:ListEngineVersions"]
    resources = ["*"]
  }

  statement {
    sid    = "ReadSecurityCatalog"
    effect = "Allow"
    actions = [
      "glue:GetDatabase", "glue:GetDatabases", "glue:GetTable", "glue:GetTables",
      "glue:GetPartition", "glue:GetPartitions", "glue:BatchGetPartition",
    ]
    resources = [
      "arn:${var.partition}:glue:${var.region}:${var.account_id}:catalog",
      "arn:${var.partition}:glue:${var.region}:${var.account_id}:database/${local.database}",
      "arn:${var.partition}:glue:${var.region}:${var.account_id}:table/${local.database}/*",
    ]
  }

  statement {
    sid       = "ReadCloudTrailObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${var.cloudtrail_bucket_arn}/${local.cloudtrail_prefix}/*"]
  }

  statement {
    sid       = "ListCloudTrailPrefix"
    effect    = "Allow"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [var.cloudtrail_bucket_arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${local.cloudtrail_prefix}/*", "${local.cloudtrail_prefix}/"]
    }
  }

  dynamic "statement" {
    for_each = var.intel_bucket_arn == null ? [] : [1]
    content {
      sid       = "ReadThreatIntel"
      effect    = "Allow"
      actions   = ["s3:GetObject", "s3:GetObjectVersion"]
      resources = ["${var.intel_bucket_arn}/indicators/*"]
    }
  }

  dynamic "statement" {
    for_each = var.intel_bucket_arn == null ? [] : [1]
    content {
      sid       = "ListThreatIntel"
      effect    = "Allow"
      actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
      resources = [var.intel_bucket_arn]
    }
  }

  dynamic "statement" {
    for_each = var.network_logs_bucket_arn == null ? [] : [1]
    content {
      sid       = "ReadNetworkLogObjects"
      effect    = "Allow"
      actions   = ["s3:GetObject"]
      resources = ["${var.network_logs_bucket_arn}/AWSLogs/${var.account_id}/vpcflowlogs/*", "${var.network_logs_bucket_arn}/route53resolver/*"]
    }
  }

  dynamic "statement" {
    for_each = var.network_logs_bucket_arn == null ? [] : [1]
    content {
      sid       = "ListNetworkLogPrefixes"
      effect    = "Allow"
      actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
      resources = [var.network_logs_bucket_arn]
    }
  }

  statement {
    sid       = "ReadWriteQueryResults"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
    resources = ["${aws_s3_bucket.results.arn}/results/*"]
  }

  statement {
    sid       = "ListQueryResults"
    effect    = "Allow"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation", "s3:ListBucketMultipartUploads"]
    resources = [aws_s3_bucket.results.arn]
  }

  dynamic "statement" {
    for_each = var.kms_key_arn == null ? [] : [1]
    content {
      sid       = "UseLabKeyForLogsAndResults"
      effect    = "Allow"
      actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
      resources = [var.kms_key_arn]
    }
  }
}

resource "aws_iam_policy" "hunter" {
  name        = "${var.name_prefix}-threat-hunter"
  description = "Run saved CloudTrail hunts in the ${var.name_prefix} Athena workgroup. Read-only on CloudTrail."
  policy      = data.aws_iam_policy_document.hunter.json
}
