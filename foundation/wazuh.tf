locals {
  wazuh_cloudtrail_prefix = "AWSLogs/${data.aws_caller_identity.current.account_id}/CloudTrail/"
  wazuh_alb_prefix        = "alb/primary/AWSLogs/${data.aws_caller_identity.current.account_id}/elasticloadbalancing/${var.primary_region}/"
  wazuh_reader_trusted_principal_arn = try(
    trimspace(var.wazuh_reader_trusted_principal_arn),
    ""
  )
  wazuh_reader_assume_principal_arn = local.wazuh_reader_trusted_principal_arn != "" ? (
    local.wazuh_reader_trusted_principal_arn
  ) : "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/wazuh-reader-principal-not-configured"
  wazuh_cloudwatch_log_groups = {
    cloudfront = {
      arn    = aws_cloudwatch_log_group.cloudfront_wazuh.arn
      name   = aws_cloudwatch_log_group.cloudfront_wazuh.name
      region = "us-east-1"
    }
    waf = {
      arn    = aws_cloudwatch_log_group.waf_edge.arn
      name   = aws_cloudwatch_log_group.waf_edge.name
      region = "us-east-1"
    }
    dvwa = {
      arn    = aws_cloudwatch_log_group.dvwa_primary.arn
      name   = aws_cloudwatch_log_group.dvwa_primary.name
      region = var.primary_region
    }
  }
}

data "aws_iam_policy_document" "wazuh_log_reader_assume" {
  count = var.enable_wazuh_log_reader ? 1 : 0

  statement {
    sid     = "AllowExplicitBootstrapPrincipal"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [local.wazuh_reader_assume_principal_arn]
    }
  }
}

resource "aws_iam_role" "wazuh_log_reader" {
  count = var.enable_wazuh_log_reader ? 1 : 0

  name                 = "${local.name}-wazuh-log-reader"
  description          = "Optional local Wazuh read-only access to approved project security log sources."
  assume_role_policy   = data.aws_iam_policy_document.wazuh_log_reader_assume[0].json
  max_session_duration = 3600

  lifecycle {
    precondition {
      condition = try(
        local.wazuh_reader_trusted_principal_arn != "" &&
        split(":", local.wazuh_reader_trusted_principal_arn)[4] == data.aws_caller_identity.current.account_id,
        false
      )
      error_message = "When enable_wazuh_log_reader is true, set wazuh_reader_trusted_principal_arn to an IAM user or role ARN in the active AWS account."
    }
  }
}

data "aws_iam_policy_document" "wazuh_log_reader" {
  count = var.enable_wazuh_log_reader ? 1 : 0

  statement {
    sid       = "ListSecurityLogBucketKeys"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.security_logs.arn]
  }

  statement {
    sid     = "ReadApprovedSecurityLogObjects"
    effect  = "Allow"
    actions = ["s3:GetObject"]
    resources = [
      "${aws_s3_bucket.security_logs.arn}/${local.wazuh_cloudtrail_prefix}*",
      "${aws_s3_bucket.security_logs.arn}/${local.wazuh_alb_prefix}*"
    ]
  }

  statement {
    sid     = "DescribeApprovedLogStreams"
    effect  = "Allow"
    actions = ["logs:DescribeLogStreams"]
    resources = [
      for source in values(local.wazuh_cloudwatch_log_groups) : "${source.arn}:*"
    ]
  }

  statement {
    sid     = "ReadApprovedLogEvents"
    effect  = "Allow"
    actions = ["logs:GetLogEvents"]
    resources = [
      for source in values(local.wazuh_cloudwatch_log_groups) : "${source.arn}:log-stream:*"
    ]
  }
}

resource "aws_iam_role_policy" "wazuh_log_reader" {
  count = var.enable_wazuh_log_reader ? 1 : 0

  name   = "read-approved-security-logs"
  role   = aws_iam_role.wazuh_log_reader[0].id
  policy = data.aws_iam_policy_document.wazuh_log_reader[0].json
}
