data "terraform_remote_state" "foundation" {
  backend = "local"

  config = {
    path = "${path.module}/foundation/terraform.tfstate"
  }
}

locals {
  security_log_bucket_name = data.terraform_remote_state.foundation.outputs.security_log_bucket_name
  security_log_bucket_arn  = data.terraform_remote_state.foundation.outputs.security_log_bucket_arn
  security_log_group_names = data.terraform_remote_state.foundation.outputs.security_log_group_names
  security_log_group_arns  = data.terraform_remote_state.foundation.outputs.security_log_group_arns
}

check "observability_foundation_contract" {
  assert {
    condition = (
      local.security_log_bucket_name != "" &&
      local.security_log_bucket_arn != "" &&
      local.security_log_group_names.eks_primary != "" &&
      local.security_log_group_names.dvwa != "" &&
      local.security_log_group_names.dvwa_dr != "" &&
      local.security_log_group_names.waf != "" &&
      data.terraform_remote_state.foundation.outputs.cloudfront_log_delivery_destination_arn != ""
    )
    error_message = "Apply the reviewed Foundation observability resources before planning the Daily Runtime."
  }
}

# CloudFront standard logging v2 keeps edge access logs in the persistent
# Foundation S3 archive. Cookie and query-string fields are intentionally
# omitted from the selected record fields.
resource "aws_cloudwatch_log_delivery_source" "cloudfront_access" {
  count        = var.enable_edge_access_logging ? 1 : 0
  provider     = aws.global
  name         = "${local.name}-cloudfront-access"
  log_type     = "ACCESS_LOGS"
  resource_arn = aws_cloudfront_distribution.this.arn
}

resource "aws_cloudwatch_log_delivery" "cloudfront_access" {
  count                    = var.enable_edge_access_logging ? 1 : 0
  provider                 = aws.global
  delivery_source_name     = aws_cloudwatch_log_delivery_source.cloudfront_access[0].name
  delivery_destination_arn = data.terraform_remote_state.foundation.outputs.cloudfront_log_delivery_destination_arn
  # The persistent destination uses JSON. Delimiters are valid only for
  # plain, w3c, or raw output formats.
  record_fields = [
    "date",
    "time",
    "x-edge-location",
    "sc-bytes",
    "c-ip",
    "cs-method",
    "cs(Host)",
    "cs-uri-stem",
    "sc-status",
    "x-edge-request-id",
    "x-host-header",
    "cs-protocol",
    "cs-bytes",
    "time-taken",
    "x-forwarded-for",
    "ssl-protocol",
    "ssl-cipher",
    "x-edge-response-result-type",
    "c-country"
  ]
}

# Start with AWS managed rules in COUNT mode. This records what would match
# without blocking the intentionally vulnerable training application.
resource "aws_wafv2_web_acl" "edge" {
  count    = var.enable_waf_observation ? 1 : 0
  provider = aws.global
  name     = "${local.name}-edge-observation"
  scope    = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "aws-managed-common-count"
    priority = 10

    override_action {
      count {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-common-count"
      sampled_requests_enabled   = true
    }
  }

  # The Common Rule Set recorded the XSS requests from the controlled BANK
  # exercise, but it does not provide the dedicated SQL injection coverage
  # needed for the observed /sqli and /sqli_blind traffic. Keep the dedicated
  # AWS managed SQLi rules in COUNT mode so the intentionally vulnerable
  # workload remains reachable while every match is retained in the WAF log.
  rule {
    name     = "aws-managed-sqli-count"
    priority = 15

    override_action {
      count {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-sqli-count"
      sampled_requests_enabled   = true
    }
  }

  # WEB-01 is disabled by default. Enabling COUNT or BLOCK is an explicit
  # experiment gate because changing a rate rule resets its tracked counters.
  dynamic "rule" {
    for_each = lower(var.waf_login_rate_rule_mode) == "disabled" ? [] : [lower(var.waf_login_rate_rule_mode)]

    content {
      # Keep one stable rule instance while only the action changes. Encoding
      # COUNT/BLOCK in the name creates a new rate tracker for every phase.
      name     = "bank-login-rate"
      priority = 20

      action {
        dynamic "count" {
          for_each = rule.value == "count" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value == "block" ? [1] : []
          content {}
        }
      }

      statement {
        rate_based_statement {
          aggregate_key_type    = "IP"
          limit                 = var.waf_login_rate_limit
          evaluation_window_sec = var.waf_login_rate_evaluation_window_seconds

          scope_down_statement {
            and_statement {
              statement {
                byte_match_statement {
                  positional_constraint = "EXACTLY"
                  search_string         = "/login.php"

                  field_to_match {
                    uri_path {}
                  }

                  text_transformation {
                    priority = 0
                    type     = "NONE"
                  }
                }
              }

              statement {
                byte_match_statement {
                  positional_constraint = "EXACTLY"
                  search_string         = "POST"

                  field_to_match {
                    method {}
                  }

                  text_transformation {
                    priority = 0
                    type     = "NONE"
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name}-bank-login-rate"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-edge"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_logging_configuration" "edge" {
  count                   = var.enable_waf_observation ? 1 : 0
  provider                = aws.global
  resource_arn            = aws_wafv2_web_acl.edge[0].arn
  log_destination_configs = [local.security_log_group_arns.waf]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }

  logging_filter {
    default_behavior = "DROP"

    filter {
      behavior    = "KEEP"
      requirement = "MEETS_ANY"

      condition {
        action_condition {
          action = "COUNT"
        }
      }

      condition {
        action_condition {
          action = "BLOCK"
        }
      }
    }
  }
}

# Only rejected traffic is retained for the first security scenarios.
resource "aws_flow_log" "primary_reject" {
  count                    = var.enable_vpc_reject_flow_logs ? 1 : 0
  provider                 = aws.primary
  log_destination          = "${local.security_log_bucket_arn}/vpc-flow"
  log_destination_type     = "s3"
  traffic_type             = "REJECT"
  vpc_id                   = module.primary_vpc.vpc_id
  max_aggregation_interval = 60
}

resource "aws_iam_role" "primary_dvwa_log_forwarder" {
  count              = var.enable_dvwa_log_collection ? 1 : 0
  provider           = aws.primary
  name               = "${local.name}-primary-dvwa-logs"
  assume_role_policy = data.aws_iam_policy_document.pod_identity_assume_role.json
}

resource "aws_iam_role_policy" "primary_dvwa_log_forwarder" {
  count    = var.enable_dvwa_log_collection ? 1 : 0
  provider = aws.primary
  role     = aws_iam_role.primary_dvwa_log_forwarder[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "WriteDvwaCloudWatchLogs"
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:DescribeLogStreams",
        "logs:PutLogEvents"
      ]
      Resource = "${local.security_log_group_arns.dvwa}:*"
    }]
  })
}

resource "aws_eks_pod_identity_association" "primary_dvwa_log_forwarder" {
  count           = var.enable_dvwa_log_collection ? 1 : 0
  provider        = aws.primary
  cluster_name    = module.primary_eks.cluster_name
  namespace       = "amazon-cloudwatch"
  service_account = "aws-for-fluent-bit"
  role_arn        = aws_iam_role.primary_dvwa_log_forwarder[0].arn
}

resource "aws_iam_role" "dr_dvwa_log_forwarder" {
  count              = local.enable_dr_runtime && var.enable_dvwa_log_collection ? 1 : 0
  provider           = aws.dr
  name               = "${local.name}-dr-dvwa-logs"
  assume_role_policy = data.aws_iam_policy_document.pod_identity_assume_role.json
}

resource "aws_iam_role_policy" "dr_dvwa_log_forwarder" {
  count    = local.enable_dr_runtime && var.enable_dvwa_log_collection ? 1 : 0
  provider = aws.dr
  role     = aws_iam_role.dr_dvwa_log_forwarder[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "WriteDvwaCloudWatchLogs"
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:DescribeLogStreams",
        "logs:PutLogEvents"
      ]
      Resource = "${local.security_log_group_arns.dvwa_dr}:*"
    }]
  })
}

resource "aws_eks_pod_identity_association" "dr_dvwa_log_forwarder" {
  count           = local.enable_dr_runtime && var.enable_dvwa_log_collection ? 1 : 0
  provider        = aws.dr
  cluster_name    = module.dr_eks[0].cluster_name
  namespace       = "amazon-cloudwatch"
  service_account = "aws-for-fluent-bit"
  role_arn        = aws_iam_role.dr_dvwa_log_forwarder[0].arn
}
