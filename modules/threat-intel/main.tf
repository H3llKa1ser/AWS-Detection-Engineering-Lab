# ---------------------------------------------------------------------------
# Curated threat intelligence for hunting
#
#   intel/indicators/*.csv  ->  validated at plan time  ->  merged into ONE
#   sorted CSV  ->  versioned, KMS-encrypted S3 object  ->  Glue table
#   threat_indicators, joined by hunts 22-25 against flow, DNS and CloudTrail.
#
# One object, sorted rows: a change to the indicator set is exactly one
# S3 PutObject (which triggers one retro-hunt), and re-ordering rows in a file
# changes nothing. Bucket versioning keeps every indicator set ever applied.
# ---------------------------------------------------------------------------

locals {
  table   = "threat_indicators"
  columns = ["indicator", "type", "source", "confidence", "added", "expires", "description", "reference"]

  files = sort(fileset(var.indicator_dir, "*.csv"))
  rows = flatten([for f in local.files : [
    for r in csvdecode(file("${var.indicator_dir}/${f}")) : merge(
      { for c in local.columns : c => trimspace(lookup(r, c, "")) },
      { indicator = lower(trimspace(lookup(r, "indicator", ""))), type = lower(trimspace(lookup(r, "type", ""))),
      confidence = lower(trimspace(lookup(r, "confidence", ""))), _file = f }
    )
  ]])

  # Plan-time checks. tests/intel/test_indicators.py enforces the full rule set
  # (address parsing, reserved ranges); these catch what would break the table
  # or match far too much.
  never_domains = ["amazonaws.com", "amazon.com", "aws.amazon.com", "cloudfront.net", "github.com",
  "googleapis.com", "google.com", "microsoft.com", "windows.net", "azure.com", "akamaiedge.net", "cloudflare.com"]

  bad_rows = [for r in local.rows : "${r._file}: ${r.indicator == "" ? "(empty)" : r.indicator}" if !(
    alltrue([for c in ["indicator", "type", "source", "confidence", "added", "expires", "description"] : r[c] != ""])
    && contains(["ipv4", "ipv6", "cidr", "domain"], r.type)
    && contains(["low", "medium", "high"], r.confidence)
    && can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", r.added))
    && can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", r.expires))
    && (r.type != "ipv4" || can(regex("^([0-9]{1,3}[.]){3}[0-9]{1,3}$", r.indicator)))
    && (r.type != "ipv6" || (can(regex(":", r.indicator)) && !can(regex("/", r.indicator)) && can(cidrhost("${r.indicator}/128", 0))))
    && (r.type != "cidr" || (can(cidrhost(r.indicator, 0)) && can(regex("/", r.indicator))
    && try(tonumber(split("/", r.indicator)[1]) >= (can(regex(":", r.indicator)) ? 32 : 16), false)))
    && (r.type != "domain" || (can(regex("^([a-z0-9_-]+[.])+[a-z0-9-]+$", r.indicator)) && !contains(local.never_domains, r.indicator)))
    && !can(regex("^(10[.]|127[.]|169[.]254[.]|192[.]168[.]|172[.](1[6-9]|2[0-9]|3[01])[.]|0[.])", r.indicator))
    && !can(regex("^(f[cd]|fe[89ab]|ff)[0-9a-f]{0,2}:|^::(1)?(/|$)|^::ffff:", r.indicator)) # IPv6 ULA, link-local, multicast, loopback, unspecified, v4-mapped
  )]

  keys      = [for r in local.rows : "${r.type}|${r.indicator}"]
  dup_keys  = distinct([for k in local.keys : k if length([for x in local.keys : x if x == k]) > 1])
  by_key    = { for r in local.rows : "${r.type}|${r.indicator}" => r... }
  csv_cell  = "\"%s\""
  csv_lines = [for k in sort(distinct(local.keys)) : join(",", [for c in local.columns : format(local.csv_cell, replace(local.by_key[k][0][c], "\"", "\"\""))])]
  content   = "${join(",", local.columns)}\n${join("\n", local.csv_lines)}\n"
}

# --- Bucket ---------------------------------------------------------------------
resource "aws_s3_bucket" "intel" {
  bucket        = var.bucket_name
  force_destroy = true # lab convenience
}

resource "aws_s3_bucket_versioning" "intel" {
  bucket = aws_s3_bucket.intel.id
  versioning_configuration { status = "Enabled" } # history of every indicator set applied
}

resource "aws_s3_bucket_public_access_block" "intel" {
  bucket                  = aws_s3_bucket.intel.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "intel" {
  bucket = aws_s3_bucket.intel.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null
  }
}

data "aws_iam_policy_document" "intel_tls" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.intel.arn, "${aws_s3_bucket.intel.arn}/*"]
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

resource "aws_s3_bucket_policy" "intel" {
  bucket = aws_s3_bucket.intel.id
  policy = data.aws_iam_policy_document.intel_tls.json
}

# Object-level events to EventBridge: the retro-hunt trigger listens for them.
resource "aws_s3_bucket_notification" "intel" {
  bucket      = aws_s3_bucket.intel.id
  eventbridge = true
}

# --- The indicator set ------------------------------------------------------------
resource "aws_s3_object" "indicators" {
  bucket       = aws_s3_bucket.intel.id
  key          = "indicators/indicators.csv"
  content      = local.content
  content_type = "text/csv"

  server_side_encryption = var.kms_key_arn == null ? "AES256" : "aws:kms"
  kms_key_id             = var.kms_key_arn

  lifecycle {
    precondition {
      condition     = length(local.files) > 0
      error_message = "No indicator files found in ${var.indicator_dir}."
    }
    precondition {
      condition     = length(local.bad_rows) == 0
      error_message = "Invalid indicators (see intel/README.md; run tests/intel/test_indicators.py for details): ${join("; ", slice(local.bad_rows, 0, min(10, length(local.bad_rows))))}"
    }
    precondition {
      condition     = length(local.dup_keys) == 0
      error_message = "Duplicate indicators across files: ${join(", ", local.dup_keys)}"
    }
  }

  # Events must be on, and the table must exist, before the object lands: the
  # upload triggers a retro-hunt that queries the table straight away. (The
  # root module also makes this wait for the retro-hunt rule.)
  depends_on = [aws_s3_bucket_notification.intel, aws_glue_catalog_table.indicators]
}

# --- Table -----------------------------------------------------------------------------
resource "aws_glue_catalog_table" "indicators" {
  name          = local.table
  database_name = var.database_name
  description   = "Curated threat indicators from intel/indicators/*.csv (all columns are strings; hunts filter on expires)."
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL                 = "TRUE"
    classification           = "csv"
    "skip.header.line.count" = "1"
  }

  storage_descriptor {
    location      = "s3://${var.bucket_name}/indicators/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.serde2.OpenCSVSerde"
      parameters = {
        separatorChar = ","
        quoteChar     = "\""
        escapeChar    = "\\"
      }
    }

    dynamic "columns" {
      for_each = local.columns
      content {
        name = columns.value
        type = "string"
      }
    }
  }
}
