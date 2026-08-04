locals {
  security_metric_namespace = "${local.name}/Security"
  guardduty_disabled_features = toset([
    "S3_DATA_EVENTS",
    "EKS_AUDIT_LOGS",
    "EBS_MALWARE_PROTECTION",
    "RDS_LOGIN_EVENTS",
    "LAMBDA_NETWORK_LOGS",
    "RUNTIME_MONITORING",
    "AI_PROTECTION",
  ])
  guardduty_runtime_monitoring_additional = toset([
    "EC2_AGENT_MANAGEMENT",
    "ECS_FARGATE_AGENT_MANAGEMENT",
    "EKS_ADDON_MANAGEMENT",
  ])
}

# This topic is the persistent notification boundary. An endpoint is optional
# because an email subscription requires an out-of-band recipient confirmation.
resource "aws_sns_topic" "security_alerts" {
  name = "${local.name}-security-alerts"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_sns_topic_subscription" "security_alert_email" {
  count = var.enable_security_alert_email_subscription ? 1 : 0

  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.security_alert_email
}

check "security_alert_email_subscription" {
  assert {
    condition = (
      !var.enable_security_alert_email_subscription ||
      can(regex(
        "^[^@ ]+@[^@ ]+\\.[^@ ]+$",
        trimspace(nonsensitive(var.security_alert_email))
      ))
    )
    error_message = "Set a valid security_alert_email when the email subscription is enabled."
  }
}

# The metric deliberately has no source_ip dimension. The reusable Logs
# Insights query performs per-IP investigation without creating unbounded
# custom-metric cardinality; this filter is only the low-cost early warning.
resource "aws_cloudwatch_log_metric_filter" "dvwa_login_failures" {
  name           = "${local.name}-dvwa-login-failures"
  log_group_name = aws_cloudwatch_log_group.dvwa_primary.name
  pattern        = "{ $.data.event_type = \"auth.login.failed\" }"

  metric_transformation {
    name          = "DVWALoginFailures"
    namespace     = local.security_metric_namespace
    value         = "1"
    default_value = 0
    unit          = "Count"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# WEB-01 currently runs against the Primary BANK service. DR log delivery is
# retained separately and will receive an alarm only after DR Runtime evidence
# proves the same audit-event shape there.
resource "aws_cloudwatch_metric_alarm" "dvwa_login_failures" {
  alarm_name          = "${local.name}-dvwa-login-failures"
  alarm_description   = "BANK DVWA emitted repeated auth.login.failed audit events within five minutes. Investigate by source IP with the WEB-01 Logs Insights query."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  metric_name         = "DVWALoginFailures"
  namespace           = local.security_metric_namespace
  period              = 300
  statistic           = "Sum"
  threshold           = var.dvwa_login_failure_alarm_threshold
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.security_alerts.arn]
  ok_actions    = [aws_sns_topic.security_alerts.arn]

  lifecycle {
    prevent_destroy = true
  }
}

# F2 uses only GuardDuty's foundational threat detection. Optional protection
# plans remain explicitly disabled so this phase does not silently expand into
# Runtime Monitoring, Malware Protection, or other higher-cost F3 scope.
resource "aws_guardduty_detector" "primary" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_guardduty_detector_feature" "disabled_optional" {
  for_each = local.guardduty_disabled_features

  detector_id = aws_guardduty_detector.primary.id
  name        = each.value
  status      = "DISABLED"

  dynamic "additional_configuration" {
    for_each = each.value == "RUNTIME_MONITORING" ? local.guardduty_runtime_monitoring_additional : []

    content {
      name   = additional_configuration.value
      status = "DISABLED"
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_log_group" "guardduty_findings" {
  name              = "/aws/events/${local.name}-guardduty-findings"
  retention_in_days = var.security_log_retention_days

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${local.name}-guardduty-findings"
  description = "Route Primary GuardDuty findings to the persistent alert and evidence boundaries."
  state       = "ENABLED"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    account       = [data.aws_caller_identity.current.account_id]
  })

  lifecycle {
    prevent_destroy = true
  }
}

# EventBridge CloudWatch Logs targets must use a resource policy and must not
# set RoleArn. Keep the write boundary on this one Foundation Log Group.
resource "aws_cloudwatch_log_resource_policy" "guardduty_eventbridge" {
  policy_name = "${local.name}-guardduty-eventbridge-logs"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowGuardDutyEventBridgeDelivery"
      Effect = "Allow"
      Principal = {
        Service = [
          "events.amazonaws.com",
          "delivery.logs.amazonaws.com",
        ]
      }
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ]
      Resource = "${aws_cloudwatch_log_group.guardduty_findings.arn}:*"
    }]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_event_target" "guardduty_log" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "guardduty-finding-log"
  arn       = aws_cloudwatch_log_group.guardduty_findings.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 3
  }

  depends_on = [aws_cloudwatch_log_resource_policy.guardduty_eventbridge]

  lifecycle {
    prevent_destroy = true
  }
}

# Use a narrowly scoped execution role for the SNS target instead of replacing
# the existing topic policy used by CloudWatch alarms and optional subscribers.
data "aws_iam_policy_document" "guardduty_eventbridge_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.guardduty_findings.arn]
    }
  }
}

resource "aws_iam_role" "guardduty_eventbridge" {
  name               = "${local.name}-guardduty-eventbridge"
  assume_role_policy = data.aws_iam_policy_document.guardduty_eventbridge_assume.json

  lifecycle {
    prevent_destroy = true
  }
}

data "aws_iam_policy_document" "guardduty_eventbridge_publish" {
  statement {
    sid       = "PublishGuardDutyFindings"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
  }
}

resource "aws_iam_role_policy" "guardduty_eventbridge_publish" {
  name   = "guardduty-finding-publish"
  role   = aws_iam_role.guardduty_eventbridge.id
  policy = data.aws_iam_policy_document.guardduty_eventbridge_publish.json

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_event_target" "guardduty_alert" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "guardduty-finding-alert"
  arn       = aws_sns_topic.security_alerts.arn
  role_arn  = aws_iam_role.guardduty_eventbridge.arn

  # Preserve the complete EventBridge event in CloudWatch Logs, but send only
  # the fields an operator needs for first response to email/SMS. Forwarding
  # the raw Finding produced twelve unordered SMS fragments during F2 runtime
  # validation and exposed unnecessary AWS session metadata.
  input_transformer {
    input_paths = {
      finding_id   = "$.detail.id"
      finding_type = "$.detail.type"
      region       = "$.region"
      resource     = "$.detail.resource.resourceType"
      severity     = "$.detail.severity"
      time         = "$.time"
    }
    # Keep EventBridge placeholders literal. jsonencode() escapes '<' as
    # '\u003c', which prevents InputTransformer from substituting them.
    input_template = "\"[GuardDuty][S<severity>] <finding_type>\\n<region> <resource>\\nID <finding_id>\\n<time>\""
  }

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 3
  }

  lifecycle {
    prevent_destroy = true
  }
}
