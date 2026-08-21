data "aws_partition" "current" {}

locals {
  security_trail_name = "${local.name}-security-trail"
  security_trail_arn  = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.primary_region}:${data.aws_caller_identity.current.account_id}:trail/${local.security_trail_name}"
}

resource "aws_s3_bucket" "security_logs" {
  bucket_prefix = "${local.name}-security-logs-"
  force_destroy = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "security_logs" {
  bucket                  = aws_s3_bucket.security_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  depends_on = [aws_s3_bucket_versioning.security_logs]

  rule {
    id     = "expire-security-evidence"
    status = "Enabled"

    filter {}

    expiration {
      days = var.security_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.security_log_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  rule {
    id     = "remove-expired-delete-markers"
    status = "Enabled"

    filter {}

    expiration {
      expired_object_delete_marker = true
    }
  }
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${local.name}-security"
  retention_in_days = var.security_log_retention_days

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_log_group" "eks_primary" {
  name              = "/aws/eks/${local.name}-primary/cluster"
  retention_in_days = var.security_log_retention_days

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_log_group" "dvwa_primary" {
  name              = "/aws/eks/${local.name}-primary/dvwa"
  retention_in_days = var.security_log_retention_days

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_log_group" "dvwa_dr" {
  provider          = aws.dr
  name              = "/aws/eks/${local.name}-dr/dvwa"
  retention_in_days = var.security_log_retention_days

  lifecycle {
    prevent_destroy = true
  }
}

# AWS WAF accepts only CloudWatch log groups whose names start with
# aws-waf-logs-. CloudFront-scoped WAF resources are managed in us-east-1.
resource "aws_cloudwatch_log_group" "waf_edge" {
  provider          = aws.global
  name              = "aws-waf-logs-${local.name}-edge"
  retention_in_days = var.security_log_retention_days

  lifecycle {
    prevent_destroy = true
  }
}

# This is a short-lived hot copy for local Wazuh polling. The existing S3
# destination remains the persistent CloudFront evidence and Athena source.
resource "aws_cloudwatch_log_group" "cloudfront_wazuh" {
  provider          = aws.global
  name              = "${local.name}-cloudfront-access-wazuh"
  retention_in_days = var.cloudfront_wazuh_log_retention_days

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_log_delivery_destination" "cloudfront_s3" {
  provider      = aws.global
  name          = "${local.name}-cloudfront-access-s3"
  output_format = "json"

  delivery_destination_configuration {
    destination_resource_arn = aws_s3_bucket.security_logs.arn
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_log_delivery_destination" "cloudfront_wazuh" {
  provider      = aws.global
  name          = "${local.name}-cloudfront-access-wazuh"
  output_format = "json"

  delivery_destination_configuration {
    destination_resource_arn = aws_cloudwatch_log_group.cloudfront_wazuh.arn
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role" "cloudtrail_logs" {
  name = "${local.name}-security-cloudtrail-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceArn" = local.security_trail_arn
        }
      }
    }]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy" "cloudtrail_logs" {
  name = "cloudwatch-delivery"
  role = aws_iam_role.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_policy" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "CloudTrailAcl"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.security_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = local.security_trail_arn
          }
        }
      },
      {
        Sid       = "CloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.security_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = local.security_trail_arn
            "s3:x-amz-acl"  = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid       = "VendedLogAclCheck"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource  = aws_s3_bucket.security_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnLike = {
            "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:logs:*:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      },
      {
        Sid       = "VendedLogWrite"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource = [
          "${aws_s3_bucket.security_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
          "${aws_s3_bucket.security_logs.arn}/vpc-flow/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        ]
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
            "s3:x-amz-acl"      = "bucket-owner-full-control"
          }
          ArnLike = {
            "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:logs:*:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      },
      {
        Sid       = "PrimaryAlbAccessLogWrite"
        Effect    = "Allow"
        Principal = { Service = "logdelivery.elasticloadbalancing.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.security_logs.arn}/alb/primary/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnLike = {
            "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:elasticloadbalancing:${var.primary_region}:${data.aws_caller_identity.current.account_id}:loadbalancer/*"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "security" {
  name                          = local.security_trail_name
  s3_bucket_name                = aws_s3_bucket.security_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_logs.arn

  # Preserve the existing management-event-only trail unless a team-approved
  # experiment explicitly opts in to chargeable S3 object data events.
  dynamic "event_selector" {
    for_each = var.enable_project_s3_data_events ? [] : [1]

    content {
      include_management_events = true
      read_write_type           = "All"
    }
  }

  dynamic "advanced_event_selector" {
    for_each = var.enable_project_s3_data_events ? [1] : []

    content {
      name = "Management events"

      field_selector {
        field  = "eventCategory"
        equals = ["Management"]
      }
    }
  }

  # Daily S3 buckets use generated suffixes. When explicitly enabled, match
  # only this project's Primary and DR bucket-name prefixes and the three
  # object operations required by a controlled validation experiment.
  dynamic "advanced_event_selector" {
    for_each = var.enable_project_s3_data_events ? [1] : []

    content {
      name = "Project S3 canary object events"

      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }

      field_selector {
        field  = "resources.type"
        equals = ["AWS::S3::Object"]
      }

      field_selector {
        field  = "eventName"
        equals = ["GetObject", "PutObject", "DeleteObject"]
      }

      field_selector {
        field = "resources.ARN"
        starts_with = [
          "arn:${data.aws_partition.current.partition}:s3:::${local.name}-primary-",
          "arn:${data.aws_partition.current.partition}:s3:::${local.name}-dr-",
          "arn:${data.aws_partition.current.partition}:s3:::${local.name}-cap1-secondary-"
        ]
      }
    }
  }

  depends_on = [aws_s3_bucket_policy.security_logs]

  lifecycle {
    prevent_destroy = true
  }
}
