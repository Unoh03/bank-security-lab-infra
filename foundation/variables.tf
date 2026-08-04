variable "aws_profile" {
  type    = string
  default = "terra-user"
}

variable "expected_account_id" {
  description = "AWS account allowed for this persistent foundation. Empty disables the check."
  type        = string
  default     = ""

  validation {
    condition     = var.expected_account_id == "" || can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "expected_account_id must be empty or a 12-digit AWS account ID."
  }
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

variable "domain_name" {
  description = "Existing Route 53 public hosted-zone domain whose DNS authority and CloudFront certificate persist across Daily Runtime cycles."
  type        = string
  default     = ""
}

variable "github_oidc_subjects" {
  description = "Exact GitHub OIDC sub claims allowed to push to ECR."
  type        = list(string)

  validation {
    condition     = alltrue([for subject in var.github_oidc_subjects : startswith(subject, "repo:")])
    error_message = "Every subject must be a complete GitHub OIDC subject beginning with repo:."
  }
}

variable "create_github_oidc_provider" {
  description = "Create the account-level GitHub Actions OIDC provider."
  type        = bool
  default     = true
}

variable "existing_github_oidc_provider_arn" {
  description = "Existing provider ARN when provider creation is disabled."
  type        = string
  default     = ""
}

variable "ecr_image_retention_count" {
  description = "Number of tagged application images retained in ECR."
  type        = number
  default     = 20

  validation {
    condition     = var.ecr_image_retention_count >= 1
    error_message = "ecr_image_retention_count must be at least 1."
  }
}

variable "security_log_retention_days" {
  description = "Retention period shared by the persistent S3 security archive and CloudWatch hot logs."
  type        = number
  default     = 30

  validation {
    condition = contains(
      [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365],
      var.security_log_retention_days
    )
    error_message = "security_log_retention_days must be a retention value supported by CloudWatch Logs."
  }
}

variable "enable_project_s3_data_events" {
  description = "Opt in to scoped S3 object data events for an approved security experiment. This can add CloudTrail data-event charges."
  type        = bool
  default     = false
}

variable "dvwa_login_failure_alarm_threshold" {
  description = "Number of BANK login failure audit events in five minutes that moves the minimal WEB-01 alarm to ALARM."
  type        = number
  default     = 5

  validation {
    condition = (
      var.dvwa_login_failure_alarm_threshold >= 1 &&
      var.dvwa_login_failure_alarm_threshold <= 100 &&
      floor(var.dvwa_login_failure_alarm_threshold) == var.dvwa_login_failure_alarm_threshold
    )
    error_message = "dvwa_login_failure_alarm_threshold must be an integer from 1 through 100."
  }
}

variable "enable_security_alert_email_subscription" {
  description = "Create an email subscription for the persistent security alert SNS topic. The recipient must confirm the subscription before delivery begins."
  type        = bool
  default     = false
}

variable "security_alert_email" {
  description = "Email endpoint used only when enable_security_alert_email_subscription is true. It is personal configuration and must not be committed."
  type        = string
  default     = ""
  sensitive   = true
}

variable "tags" {
  type    = map(string)
  default = { Environment = "production" }
}
