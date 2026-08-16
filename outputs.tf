output "cloudfront_domain_name" {
  value = aws_cloudfront_distribution.this.domain_name
}
output "application_url" {
  value = local.domain_name == "" ? "https://${aws_cloudfront_distribution.this.domain_name}" : "https://${local.domain_name}"
}
output "primary_alb_dns_name" {
  value = aws_lb.primary.dns_name
}
output "dr_alb_dns_name" {
  value = try(aws_lb.dr[0].dns_name, null)
}
output "primary_eks_cluster_name" {
  value = module.primary_eks.cluster_name
}
output "dr_eks_cluster_name" {
  value = try(module.dr_eks[0].cluster_name, null)
}
output "primary_bastion_instance_id" {
  value = aws_instance.primary_bastion.id
}
output "seoul_bastion_public_ip" {
  description = "Public IPv4 address of the Seoul Bastion host."
  value       = aws_instance.primary_bastion.public_ip
}
output "dr_bastion_instance_id" {
  value = try(aws_instance.dr_bastion[0].id, null)
}
output "tokyo_bastion_public_ip" {
  description = "Public IPv4 address of the Tokyo Bastion host."
  value       = try(aws_instance.dr_bastion[0].public_ip, null)
}
output "primary_efs_file_system_id" {
  value = try(aws_efs_file_system.primary[0].id, null)
}
output "dr_efs_file_system_id" {
  value = try(aws_efs_file_system.dr[0].id, null)
}
output "primary_web_s3_role_arn" {
  value = try(aws_iam_role.primary_web_s3[0].arn, null)
}
output "dr_web_s3_role_arn" {
  value = try(aws_iam_role.dr_web_s3[0].arn, null)
}
output "web_s3_pod_identity_enabled" {
  description = "Whether the optional web-app S3 Pod Identity path is present."
  value       = var.enable_web_s3_pod_identity
}
output "primary_application_bucket_name" {
  description = "Primary application S3 bucket used by the scoped IAM-01 canary."
  value       = aws_s3_bucket.primary.id
}
output "dr_application_bucket_name" {
  description = "DR application S3 bucket."
  value       = try(aws_s3_bucket.dr[0].id, null)
}
output "waf_login_rate_rule_mode" {
  description = "Effective WEB-01 login rate rule mode."
  value       = lower(var.waf_login_rate_rule_mode)
}
output "primary_rds_endpoint" {
  value     = aws_db_instance.primary.endpoint
  sensitive = true
}
output "primary_db_bootstrap" {
  description = "Sensitive bootstrap material consumed in memory by daily-up.ps1."
  sensitive   = true
  value = {
    host           = aws_db_instance.primary.address
    port           = aws_db_instance.primary.port
    admin_username = var.db_username
    admin_password = random_password.db_master.result
    app_database   = var.dvwa_database_name
    app_username   = var.dvwa_database_username
    app_password   = random_password.dvwa_app.result
  }
}
output "dr_rds_endpoint" {
  value     = try(aws_db_instance.dr_replica[0].endpoint, null)
  sensitive = true
}
output "primary_valkey_endpoint" {
  value     = try(aws_elasticache_replication_group.primary[0].primary_endpoint_address, null)
  sensitive = true
}
output "dr_valkey_endpoint" {
  value     = try(aws_elasticache_replication_group.dr[0].primary_endpoint_address, null)
  sensitive = true
}
output "primary_cluster_addons_association_id" {
  description = "SSM association that installs and reconciles primary EKS add-ons."
  value       = aws_ssm_association.primary_cluster_addons.id
}

output "runtime_profile" {
  description = "Runtime profile applied to the current Daily state."
  value       = var.runtime_profile
}

output "security_scenario_profile" {
  description = "Security scenario profile applied to the current Daily state."
  value       = var.security_scenario_profile
}

output "security_scenario_features" {
  description = "Non-sensitive expected security controls for the selected scenario."
  value = {
    primary_metadata_options         = local.primary_karpenter_metadata_options
    primary_validation_read_enabled  = local.capital_one_lab_enabled
    cloudfront_wazuh_logging_enabled = local.cloudfront_wazuh_logging_enabled
    dr_metadata_options              = local.hardened_karpenter_metadata_options
    dr_validation_read_enabled       = false
  }
}

output "runtime_features" {
  description = "Explicit optional Daily Runtime feature selection."
  value = {
    valkey         = var.enable_valkey
    efs            = var.enable_efs
    https_redirect = var.enable_https_redirect
  }
}
