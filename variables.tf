variable "aws_profile" {
  type    = string
  default = "terra-user"
}
variable "project_name" {
  type    = string
  default = "aws-topology"
}
variable "primary_region" {
  type    = string
  default = "ap-northeast-2"
}
variable "dr_region" {
  type    = string
  default = "ap-northeast-1"
}
variable "primary_vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}
variable "primary_azs" {
  type    = list(string)
  default = ["ap-northeast-2a", "ap-northeast-2c"]
}
variable "primary_public_subnets" {
  type    = list(string)
  default = ["10.0.0.0/24", "10.0.1.0/24"]
}
variable "primary_private_subnets" {
  type    = list(string)
  default = ["10.0.10.0/24", "10.0.11.0/24"]
}
variable "primary_database_subnets" {
  type    = list(string)
  default = ["10.0.20.0/24", "10.0.21.0/24"]
}
variable "dr_vpc_cidr" {
  type    = string
  default = "10.10.0.0/16"
}
variable "dr_azs" {
  type    = list(string)
  default = ["ap-northeast-1a", "ap-northeast-1c"]
}
variable "dr_public_subnets" {
  type    = list(string)
  default = ["10.10.0.0/24", "10.10.1.0/24"]
}
variable "dr_private_subnets" {
  type    = list(string)
  default = ["10.10.10.0/24", "10.10.11.0/24"]
}
variable "dr_database_subnets" {
  type    = list(string)
  default = ["10.10.20.0/24", "10.10.21.0/24"]
}
variable "single_nat_gateway" {
  description = "Use one NAT gateway per region to reduce cost; false provides AZ-level HA."
  type        = bool
  default     = true
}
variable "kubernetes_version" {
  type    = string
  default = "1.35"
}
variable "node_instance_types" {
  type    = list(string)
  default = ["t3.medium"]
}
variable "bastion_instance_type" {
  description = "Instance type for the SSM-only regional bastions."
  type        = string
  default     = "t3.micro"
}
variable "primary_bastion_key_pair_name" {
  description = "AWS EC2 Key Pair name attached to the Seoul Bastion. This is the AWS name, not the local .pem path."
  type        = string
  default     = "seoul-public-ec2-key"
}
variable "dr_bastion_key_pair_name" {
  description = "AWS EC2 Key Pair name attached to the Tokyo Bastion. This is the AWS name, not the local .pem path."
  type        = string
  default     = "tokyo-public-ec2-key"
}
variable "bastion_ssh_cidrs" {
  description = "IPv4 CIDRs allowed to connect to both regional Bastions over SSH. Restrict this to administrator public IPs in production."
  type        = list(string)
  default     = []
}
variable "helm_cli_version" {
  description = "Helm CLI version installed by the regional bastion bootstrap."
  type        = string
  default     = "v3.18.4"
}
variable "enable_argocd" {
  description = "Install Argo CD in the primary EKS cluster through the SSM Bastion add-on workflow."
  type        = bool
  default     = true
}
variable "enable_dr_argocd" {
  description = "Also install Argo CD in the warm-standby DR EKS cluster. Keep false until DR deployment is intentionally enabled."
  type        = bool
  default     = false
}
variable "argocd_chart_version" {
  description = "Pinned version of the argo-cd Helm chart."
  type        = string
  default     = "8.5.8"
}
variable "enable_edge_access_logging" {
  description = "Deliver CloudFront and primary ALB access logs to the persistent Foundation archive."
  type        = bool
  default     = true
}
variable "enable_waf_observation" {
  description = "Attach a CloudFront-scoped WAF Web ACL using AWS managed rules in COUNT mode."
  type        = bool
  default     = true
}
variable "waf_login_rate_rule_mode" {
  description = "Controlled WEB-01 login rate rule mode. Keep disabled outside an approved experiment."
  type        = string
  default     = "disabled"

  validation {
    condition     = contains(["disabled", "count", "block"], lower(var.waf_login_rate_rule_mode))
    error_message = "waf_login_rate_rule_mode must be disabled, count, or block."
  }
}
variable "waf_login_rate_limit" {
  description = "Maximum /login.php POST request rate per source IP for the controlled WEB-01 rule."
  type        = number
  default     = 10

  validation {
    condition     = var.waf_login_rate_limit >= 10 && var.waf_login_rate_limit <= 2000000000
    error_message = "waf_login_rate_limit must be between 10 and 2000000000."
  }
}
variable "waf_login_rate_evaluation_window_seconds" {
  description = "AWS WAF rate evaluation window for the controlled WEB-01 rule."
  type        = number
  default     = 60

  validation {
    condition     = contains([60, 120, 300, 600], var.waf_login_rate_evaluation_window_seconds)
    error_message = "waf_login_rate_evaluation_window_seconds must be 60, 120, 300, or 600."
  }
}
variable "enable_vpc_reject_flow_logs" {
  description = "Archive rejected primary VPC traffic without collecting all accepted flows."
  type        = bool
  default     = true
}
variable "enable_dvwa_log_collection" {
  description = "Install AWS for Fluent Bit and forward only the DVWA namespace container logs."
  type        = bool
  default     = true
}
variable "aws_for_fluent_bit_chart_version" {
  description = "Pinned aws-for-fluent-bit Helm chart version."
  type        = string
  default     = "0.2.0"
}
variable "manage_addons_via_local_helm" {
  description = "Use local Helm providers instead of the default SSM Bastion deployment path. Requires direct network access to the private EKS APIs."
  type        = bool
  default     = false
}
variable "karpenter_chart_version" {
  description = "Karpenter Helm chart version installed in each enabled EKS cluster."
  type        = string
  default     = "1.6.0"
}
variable "karpenter_capacity_types" {
  description = "EC2 capacity types that Karpenter may provision."
  type        = list(string)
  default     = ["on-demand"]
}
variable "karpenter_cpu_limit" {
  description = "Maximum aggregate CPU managed by each Karpenter NodePool."
  type        = string
  default     = "20"
}
variable "web_namespace" {
  description = "Namespace used by the web application ServiceAccount."
  type        = string
  default     = "dvwa"
}
variable "web_service_account" {
  description = "ServiceAccount whose Pods may access the application S3 bucket."
  type        = string
  default     = "web-app"
}
variable "enable_web_s3_pod_identity" {
  description = "Create the dormant web-app S3 Pod Identity path. Enable only for an approved IAM-01 before-state or an implemented application requirement."
  type        = bool
  default     = false
}
variable "web_service_name" {
  description = "Kubernetes Service registered in the regional ALB target group."
  type        = string
  default     = "dvwa"
}
variable "web_service_port" {
  description = "Kubernetes Service port and ALB target group port for the web application."
  type        = number
  default     = 80
}
variable "web_health_check_path" {
  description = "Unauthenticated HTTP health check path used by the regional ALB target groups."
  type        = string
  default     = "/login.php"
}
variable "enable_dr_compute" {
  description = "Provision the warm DR EKS cluster and ALB."
  type        = bool
  default     = true
}
variable "enable_dr_external_dns" {
  description = "Allow DR ExternalDNS to modify the shared hosted zone during an intentional failover."
  type        = bool
  default     = false
}
variable "domain_name" {
  description = "Existing Route 53 public hosted-zone domain. Leave empty to skip DNS and ACM."
  type        = string
  default     = ""
}
variable "create_route53_zone" {
  type    = bool
  default = false
}
variable "db_name" {
  type    = string
  default = "appdb"
}
variable "db_username" {
  type    = string
  default = "dbadmin"
}
variable "dvwa_database_name" {
  description = "Dedicated MariaDB database created for DVWA after each daily apply."
  type        = string
  default     = "dvwa"

  validation {
    condition     = can(regex("^[A-Za-z0-9_]+$", var.dvwa_database_name))
    error_message = "dvwa_database_name may contain only letters, digits, and underscores."
  }
}
variable "dvwa_database_username" {
  description = "Dedicated MariaDB user created for the DVWA application."
  type        = string
  default     = "dvwa"

  validation {
    condition     = can(regex("^[A-Za-z0-9_]+$", var.dvwa_database_username))
    error_message = "dvwa_database_username may contain only letters, digits, and underscores."
  }
}
variable "db_instance_class" {
  type    = string
  default = "db.t4g.micro"
}
variable "tags" {
  type    = map(string)
  default = { Environment = "production" }
}
