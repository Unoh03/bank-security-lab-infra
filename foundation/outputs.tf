output "aws_account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "foundation_contract_version" {
  description = "Version of the outputs required by Daily Runtime wrappers and remote-state consumers."
  value       = 2
}

output "aws_region" {
  value = var.primary_region
}

output "application_ecr_repository_name" {
  value = aws_ecr_repository.application.name
}

output "application_ecr_repository_url" {
  value = aws_ecr_repository.application.repository_url
}

output "github_actions_role_arn" {
  value = aws_iam_role.github_actions_ecr.arn
}

output "github_oidc_provider_arn" {
  value = local.github_oidc_provider_arn
}

output "security_log_bucket_name" {
  value = aws_s3_bucket.security_logs.id
}

output "security_log_bucket_arn" {
  value = aws_s3_bucket.security_logs.arn
}

output "security_log_retention_days" {
  value = var.security_log_retention_days
}

output "security_cloudtrail_name" {
  value = aws_cloudtrail.security.name
}

output "project_s3_data_events_enabled" {
  description = "Whether project application-bucket S3 object data events are recorded."
  value       = var.enable_project_s3_data_events
}

output "security_cloudwatch_log_group_name" {
  value = aws_cloudwatch_log_group.cloudtrail.name
}

output "security_log_group_names" {
  value = {
    cloudtrail         = aws_cloudwatch_log_group.cloudtrail.name
    eks_primary        = aws_cloudwatch_log_group.eks_primary.name
    dvwa               = aws_cloudwatch_log_group.dvwa_primary.name
    dvwa_dr            = aws_cloudwatch_log_group.dvwa_dr.name
    waf                = aws_cloudwatch_log_group.waf_edge.name
    guardduty_findings = aws_cloudwatch_log_group.guardduty_findings.name
  }
}

output "security_log_group_arns" {
  value = {
    cloudtrail         = aws_cloudwatch_log_group.cloudtrail.arn
    eks_primary        = aws_cloudwatch_log_group.eks_primary.arn
    dvwa               = aws_cloudwatch_log_group.dvwa_primary.arn
    dvwa_dr            = aws_cloudwatch_log_group.dvwa_dr.arn
    waf                = aws_cloudwatch_log_group.waf_edge.arn
    guardduty_findings = aws_cloudwatch_log_group.guardduty_findings.arn
  }
}

output "cloudfront_log_delivery_destination_arn" {
  value = aws_cloudwatch_log_delivery_destination.cloudfront_s3.arn
}

output "security_alert_topic_arn" {
  value = aws_sns_topic.security_alerts.arn
}

output "dvwa_login_failure_alarm_name" {
  value = aws_cloudwatch_metric_alarm.dvwa_login_failures.alarm_name
}

output "capital_one_s3_detection" {
  description = "Non-sensitive status and identifiers for the opt-in Capital One CloudTrail detector."
  value = {
    enabled            = var.enable_capital_one_s3_detection
    metric_filter_name = try(aws_cloudwatch_log_metric_filter.capital_one_validation_getobject[0].name, null)
    alarm_name         = try(aws_cloudwatch_metric_alarm.capital_one_validation_getobject[0].alarm_name, null)
    expected_role_name = "${var.project_name}-primary-karpenter-node"
    object_prefix      = "validation/"
  }
}

output "security_alert_email_subscription_enabled" {
  value = var.enable_security_alert_email_subscription
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.primary.id
}

output "guardduty_optional_features" {
  value = {
    for name, feature in aws_guardduty_detector_feature.disabled_optional :
    name => feature.status
  }
}

output "guardduty_finding_event_rule_name" {
  value = aws_cloudwatch_event_rule.guardduty_findings.name
}

output "guardduty_finding_log_group_name" {
  value = aws_cloudwatch_log_group.guardduty_findings.name
}

output "domain_name" {
  value = var.domain_name
}

output "route53_zone_id" {
  value = var.domain_name == "" ? "" : data.aws_route53_zone.existing[0].zone_id
}

output "cloudfront_acm_certificate_arn" {
  value = var.domain_name == "" ? "" : aws_acm_certificate_validation.cloudfront[0].certificate_arn
}
