# ---------------------------------------------------------------------------
# Network log lake: VPC Flow Logs and Resolver query logs in S3 as Parquet,
# with Athena tables, so hunting can join network and DNS with CloudTrail.
#
#   Flow logs  VPC Flow Logs write Parquet natively (a second, S3-destined
#              flow log per VPC; created in the vpc-flow-logs module).
#   DNS        Resolver query logging cannot write Parquet, so it sends JSON
#              to Firehose, which converts each record to Parquet using the
#              Glue table below as its schema. The same table is what Athena
#              queries, so conversion and querying can never disagree.
#   Tables     Partition projection on dt = yyyy/MM/dd, the same scheme as the
#              CloudTrail table, so every hunt filters dates the same way.
# ---------------------------------------------------------------------------

locals {
  flow_prefix = "AWSLogs/${var.account_id}/vpcflowlogs/${var.region}"
  dns_prefix  = "route53resolver/AWSLogs/${var.account_id}/${var.region}"
  flow_table  = "vpc_flow_logs"
  dns_table   = "resolver_query_logs"

  # Parquet types as AWS documents them for flow logs (version 2-5 fields).
  # A mismatch (e.g. protocol as int instead of bigint) fails at query time.
  # Order and names must match flow_log_format in modules/vpc-flow-logs.
  flow_columns = [
    ["version", "int"], ["account_id", "string"], ["interface_id", "string"],
    ["srcaddr", "string"], ["dstaddr", "string"], ["srcport", "int"], ["dstport", "int"],
    ["protocol", "bigint"], ["packets", "bigint"], ["bytes", "bigint"],
    ["start", "bigint"], ["end", "bigint"], ["action", "string"], ["log_status", "string"],
    ["vpc_id", "string"], ["subnet_id", "string"], ["instance_id", "string"],
    ["tcp_flags", "int"], ["type", "string"], ["pkt_srcaddr", "string"], ["pkt_dstaddr", "string"],
    ["flow_direction", "string"], ["pkt_src_aws_service", "string"], ["pkt_dst_aws_service", "string"],
    ["traffic_path", "int"],
  ]

  # Resolver query log fields (JSON). Firehose's OpenX deserializer matches
  # keys case-insensitively, so answers[].Rdata lands in answers[].rdata.
  dns_columns = [
    ["version", "string"], ["account_id", "string"], ["region", "string"], ["vpc_id", "string"],
    ["query_timestamp", "string"], ["query_name", "string"], ["query_type", "string"],
    ["query_class", "string"], ["rcode", "string"],
    ["answers", "array<struct<rdata:string,type:string,class:string>>"],
    ["srcaddr", "string"], ["srcport", "string"], ["transport", "string"],
    ["srcids", "struct<instance:string,resolver_endpoint:string>"],
    ["firewall_rule_action", "string"], ["firewall_rule_group_id", "string"],
    ["firewall_domain_list_id", "string"],
  ]

  projection = {
    "projection.enabled"          = "true"
    "projection.dt.type"          = "date"
    "projection.dt.format"        = "yyyy/MM/dd"
    "projection.dt.range"         = "${var.projection_start},NOW"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "DAYS"
  }
}

# --- Bucket -------------------------------------------------------------------
resource "aws_s3_bucket" "network" {
  bucket        = var.bucket_name
  force_destroy = true # lab convenience
}

resource "aws_s3_bucket_public_access_block" "network" {
  bucket                  = aws_s3_bucket.network.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "network" {
  bucket = aws_s3_bucket.network.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "network" {
  bucket = aws_s3_bucket.network.id
  rule {
    id     = "expire-network-logs"
    status = "Enabled"
    filter {}
    expiration { days = var.retention_days }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

data "aws_iam_policy_document" "network_bucket" {
  # VPC Flow Logs (vended log delivery) writes under AWSLogs/<account>/.
  statement {
    sid       = "AWSLogDeliveryWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.network.arn}/AWSLogs/${var.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${var.partition}:logs:${var.region}:${var.account_id}:*"]
    }
  }

  statement {
    sid       = "AWSLogDeliveryAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.network.arn]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${var.partition}:logs:${var.region}:${var.account_id}:*"]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.network.arn, "${aws_s3_bucket.network.arn}/*"]
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

resource "aws_s3_bucket_policy" "network" {
  bucket = aws_s3_bucket.network.id
  policy = data.aws_iam_policy_document.network_bucket.json
}

# --- Athena tables --------------------------------------------------------------
resource "aws_glue_catalog_table" "flow" {
  count = var.enable_flow ? 1 : 0

  name          = local.flow_table
  database_name = var.database_name
  description   = "VPC Flow Logs (Parquet, native) from s3://${var.bucket_name}/${local.flow_prefix}/"
  table_type    = "EXTERNAL_TABLE"

  parameters = merge(local.projection, {
    EXTERNAL                    = "TRUE"
    classification              = "parquet"
    "storage.location.template" = "s3://${var.bucket_name}/${local.flow_prefix}/$${dt}"
  })

  partition_keys {
    name    = "dt"
    type    = "string"
    comment = "Delivery day, yyyy/MM/dd. Always filter on it."
  }

  storage_descriptor {
    location      = "s3://${var.bucket_name}/${local.flow_prefix}/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"
    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }
    dynamic "columns" {
      for_each = local.flow_columns
      content {
        name = columns.value[0]
        type = columns.value[1]
      }
    }
  }
}

resource "aws_glue_catalog_table" "dns" {
  count = var.enable_dns ? 1 : 0

  name          = local.dns_table
  database_name = var.database_name
  description   = "Route 53 Resolver query logs, converted to Parquet by Firehose, from s3://${var.bucket_name}/${local.dns_prefix}/. Also Firehose's conversion schema."
  table_type    = "EXTERNAL_TABLE"

  parameters = merge(local.projection, {
    EXTERNAL                    = "TRUE"
    classification              = "parquet"
    "storage.location.template" = "s3://${var.bucket_name}/${local.dns_prefix}/$${dt}"
  })

  partition_keys {
    name    = "dt"
    type    = "string"
    comment = "Firehose arrival day (UTC), yyyy/MM/dd. Always filter on it."
  }

  storage_descriptor {
    location      = "s3://${var.bucket_name}/${local.dns_prefix}/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"
    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }
    dynamic "columns" {
      for_each = local.dns_columns
      content {
        name = columns.value[0]
        type = columns.value[1]
      }
    }
  }
}

# --- Firehose: Resolver JSON -> Parquet -------------------------------------------
# Conversion failures are written under route53resolver-errors/ and logged to
# CloudWatch, so a schema mismatch is visible instead of silently dropping data.
resource "aws_cloudwatch_log_group" "firehose" {
  count             = var.enable_dns ? 1 : 0
  name              = "/${var.name_prefix}/firehose/dns-to-parquet"
  retention_in_days = 30
  kms_key_id        = var.kms_key_arn
}

resource "aws_cloudwatch_log_stream" "firehose" {
  count          = var.enable_dns ? 1 : 0
  name           = "S3Delivery"
  log_group_name = aws_cloudwatch_log_group.firehose[0].name
}

data "aws_iam_policy_document" "firehose_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_iam_role" "firehose" {
  count              = var.enable_dns ? 1 : 0
  name               = "${var.name_prefix}-dns-to-parquet"
  assume_role_policy = data.aws_iam_policy_document.firehose_assume.json
}

data "aws_iam_policy_document" "firehose" {
  count = var.enable_dns ? 1 : 0

  statement {
    sid    = "WriteDnsPrefixes"
    effect = "Allow"
    actions = [
      "s3:PutObject", "s3:GetObject", "s3:AbortMultipartUpload",
      "s3:ListBucketMultipartUploads",
    ]
    resources = [
      "${aws_s3_bucket.network.arn}/route53resolver/*",
      "${aws_s3_bucket.network.arn}/route53resolver-errors/*",
    ]
  }
  statement {
    sid       = "LocateBucket"
    effect    = "Allow"
    actions   = ["s3:GetBucketLocation", "s3:ListBucket"]
    resources = [aws_s3_bucket.network.arn]
  }
  statement {
    sid     = "ReadConversionSchema"
    effect  = "Allow"
    actions = ["glue:GetTable", "glue:GetTableVersion", "glue:GetTableVersions"]
    resources = [
      "arn:${var.partition}:glue:${var.region}:${var.account_id}:catalog",
      "arn:${var.partition}:glue:${var.region}:${var.account_id}:database/${var.database_name}",
      "arn:${var.partition}:glue:${var.region}:${var.account_id}:table/${var.database_name}/${local.dns_table}",
    ]
  }
  statement {
    sid       = "LogDeliveryErrors"
    effect    = "Allow"
    actions   = ["logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.firehose[0].arn}:*"]
  }
  dynamic "statement" {
    for_each = var.kms_key_arn == null ? [] : [1]
    content {
      sid       = "EncryptObjects"
      effect    = "Allow"
      actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
      resources = [var.kms_key_arn]
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["s3.${var.region}.amazonaws.com"]
      }
    }
  }
}

resource "aws_iam_role_policy" "firehose" {
  count  = var.enable_dns ? 1 : 0
  name   = "${var.name_prefix}-dns-to-parquet"
  role   = aws_iam_role.firehose[0].id
  policy = data.aws_iam_policy_document.firehose[0].json
}

resource "aws_kinesis_firehose_delivery_stream" "dns" {
  count       = var.enable_dns ? 1 : 0
  name        = "${var.name_prefix}-dns-query-logs-parquet"
  destination = "extended_s3"

  server_side_encryption {
    enabled  = true
    key_type = "AWS_OWNED_CMK"
  }

  extended_s3_configuration {
    role_arn    = aws_iam_role.firehose[0].arn
    bucket_arn  = aws_s3_bucket.network.arn
    kms_key_arn = var.kms_key_arn

    # Same yyyy/MM/dd layout as CloudTrail and flow logs, in UTC.
    prefix              = "${local.dns_prefix}/!{timestamp:yyyy/MM/dd}/"
    error_output_prefix = "route53resolver-errors/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd}/"
    file_extension      = ".parquet"

    buffering_size     = 64 # MiB; the minimum Firehose allows with format conversion
    buffering_interval = var.firehose_buffer_seconds

    data_format_conversion_configuration {
      input_format_configuration {
        deserializer {
          open_x_json_ser_de {
            case_insensitive = true
          }
        }
      }
      output_format_configuration {
        serializer {
          parquet_ser_de {
            compression = "SNAPPY"
          }
        }
      }
      schema_configuration {
        database_name = var.database_name
        table_name    = aws_glue_catalog_table.dns[0].name
        role_arn      = aws_iam_role.firehose[0].arn
        region        = var.region
      }
    }

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose[0].name
      log_stream_name = aws_cloudwatch_log_stream.firehose[0].name
    }
  }

  # AWS adds this tag itself when Resolver starts delivering, and the
  # AWSServiceRoleForLogDelivery role only writes to streams that carry it.
  # Declaring it here prevents Terraform from stripping it on the next apply,
  # which would silently stop DNS delivery.
  tags = {
    LogDeliveryEnabled = "true"
  }

  depends_on = [aws_iam_role_policy.firehose]
}
