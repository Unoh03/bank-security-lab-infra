terraform {
  required_version = ">= 1.8.0"

  required_providers {
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }

    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region  = var.primary_region
  profile = var.aws_profile == "" ? null : var.aws_profile

  default_tags {
    tags = local.common_tags
  }
}

provider "aws" {
  alias   = "dr"
  region  = var.dr_region
  profile = var.aws_profile == "" ? null : var.aws_profile

  default_tags {
    tags = local.common_tags
  }
}

provider "aws" {
  alias   = "global"
  region  = "us-east-1"
  profile = var.aws_profile == "" ? null : var.aws_profile

  default_tags {
    tags = local.common_tags
  }
}

data "aws_caller_identity" "current" {}

locals {
  name = var.project_name
  common_tags = merge(var.tags, {
    Project   = var.project_name
    ManagedBy = "Terraform"
    Lifecycle = "persistent-foundation"
  })
  github_oidc_provider_arn = var.create_github_oidc_provider ? (
    aws_iam_openid_connect_provider.github_actions[0].arn
  ) : var.existing_github_oidc_provider_arn
}

check "expected_account" {
  assert {
    condition = (
      var.expected_account_id == "" ||
      data.aws_caller_identity.current.account_id == var.expected_account_id
    )
    error_message = "The active AWS account does not match expected_account_id."
  }
}

check "github_oidc_subjects" {
  assert {
    condition     = length(var.github_oidc_subjects) > 0
    error_message = "At least one exact GitHub OIDC subject is required."
  }
}

check "existing_github_oidc_provider" {
  assert {
    condition = (
      var.create_github_oidc_provider ||
      var.existing_github_oidc_provider_arn != ""
    )
    error_message = "Set existing_github_oidc_provider_arn when provider creation is disabled."
  }
}

resource "aws_ecr_repository" "application" {
  name                 = "${local.name}/application"
  image_tag_mutability = "IMMUTABLE"

  encryption_configuration {
    encryption_type = "AES256"
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecr_lifecycle_policy" "application" {
  repository = aws_ecr_repository.application.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Retain the newest tagged application images"
      selection = {
        tagStatus     = "tagged"
        tagPrefixList = ["v", "sha-"]
        countType     = "imageCountMoreThan"
        countNumber   = var.ecr_image_retention_count
      }
      action = { type = "expire" }
    }]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_openid_connect_provider" "github_actions" {
  count = var.create_github_oidc_provider ? 1 : 0

  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]

  lifecycle {
    prevent_destroy = true
  }
}

data "aws_iam_policy_document" "github_actions_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = var.github_oidc_subjects
    }
  }
}

resource "aws_iam_role" "github_actions_ecr" {
  name               = "${local.name}-github-actions-ecr"
  assume_role_policy = data.aws_iam_policy_document.github_actions_assume_role.json

  lifecycle {
    prevent_destroy = true
  }
}

data "aws_iam_policy_document" "github_actions_ecr" {
  statement {
    sid       = "ECRAuthentication"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid    = "PushApplicationImages"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart"
    ]
    resources = [aws_ecr_repository.application.arn]
  }
}

resource "aws_iam_role_policy" "github_actions_ecr" {
  name   = "ecr-push"
  role   = aws_iam_role.github_actions_ecr.id
  policy = data.aws_iam_policy_document.github_actions_ecr.json

  lifecycle {
    prevent_destroy = true
  }
}
