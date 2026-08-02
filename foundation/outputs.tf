output "aws_account_id" {
  value = data.aws_caller_identity.current.account_id
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
    cloudtrail  = aws_cloudwatch_log_group.cloudtrail.name
    eks_primary = aws_cloudwatch_log_group.eks_primary.name
    dvwa        = aws_cloudwatch_log_group.dvwa_primary.name
    dvwa_dr     = aws_cloudwatch_log_group.dvwa_dr.name
    waf         = aws_cloudwatch_log_group.waf_edge.name
  }
}

output "security_log_group_arns" {
  value = {
    cloudtrail  = aws_cloudwatch_log_group.cloudtrail.arn
    eks_primary = aws_cloudwatch_log_group.eks_primary.arn
    dvwa        = aws_cloudwatch_log_group.dvwa_primary.arn
    dvwa_dr     = aws_cloudwatch_log_group.dvwa_dr.arn
    waf         = aws_cloudwatch_log_group.waf_edge.arn
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

output "security_alert_email_subscription_enabled" {
  value = var.enable_security_alert_email_subscription
}
