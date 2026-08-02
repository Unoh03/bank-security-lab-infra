locals {
  security_metric_namespace = "${local.name}/Security"
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
