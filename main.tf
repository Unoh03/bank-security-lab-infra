terraform {
  required_version = ">= 1.8.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
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
  alias   = "primary"
  region  = var.primary_region
  profile = var.aws_profile == "" ? null : var.aws_profile

  default_tags {
    tags = local.common_tags
  }
}

provider "helm" {
  alias = "primary"

  kubernetes = {
    host                   = module.primary_eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.primary_eks.cluster_certificate_authority_data)

    exec = {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args = concat([
        "eks", "get-token",
        "--cluster-name", module.primary_eks.cluster_name,
        "--region", var.primary_region
      ], var.aws_profile == "" ? [] : ["--profile", var.aws_profile])
    }
  }
}

provider "helm" {
  alias = "dr"

  kubernetes = {
    host                   = try(module.dr_eks[0].cluster_endpoint, "https://127.0.0.1")
    cluster_ca_certificate = try(base64decode(module.dr_eks[0].cluster_certificate_authority_data), "")

    exec = {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args = concat([
        "eks", "get-token",
        "--cluster-name", try(module.dr_eks[0].cluster_name, "disabled"),
        "--region", var.dr_region
      ], var.aws_profile == "" ? [] : ["--profile", var.aws_profile])
    }
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

# CloudFront ACM certificates must be created in us-east-1.
provider "aws" {
  alias   = "global"
  region  = "us-east-1"
  profile = var.aws_profile == "" ? null : var.aws_profile

  default_tags {
    tags = local.common_tags
  }
}

data "aws_caller_identity" "current" {
  provider = aws.primary
}

locals {
  name = var.project_name
  common_tags = merge(var.tags, {
    Project   = var.project_name
    ManagedBy = "Terraform"
  })
  runtime_profiles = {
    minimal = {
      enable_dr_runtime    = false
      primary_node_count   = 1
      primary_node_max     = 2
      primary_rds_multi_az = false
    }
    dr-test = {
      enable_dr_runtime    = true
      primary_node_count   = 1
      primary_node_max     = 2
      primary_rds_multi_az = false
    }
    full = {
      enable_dr_runtime    = true
      primary_node_count   = 2
      primary_node_max     = 4
      primary_rds_multi_az = true
    }
  }
  selected_runtime_profile = local.runtime_profiles[var.runtime_profile]
  enable_dr_runtime        = local.selected_runtime_profile.enable_dr_runtime
  primary_node_count       = local.selected_runtime_profile.primary_node_count
  primary_node_max         = local.selected_runtime_profile.primary_node_max
  primary_rds_multi_az     = local.selected_runtime_profile.primary_rds_multi_az
}

module "primary_vpc" {
  providers = { aws = aws.primary }
  source    = "terraform-aws-modules/vpc/aws"
  version   = "~> 6.0"

  name = "${local.name}-primary"
  cidr = var.primary_vpc_cidr
  azs  = var.primary_azs

  public_subnets   = var.primary_public_subnets
  private_subnets  = var.primary_private_subnets
  database_subnets = var.primary_database_subnets

  create_database_subnet_group = true
  enable_nat_gateway           = true
  single_nat_gateway           = var.single_nat_gateway
  one_nat_gateway_per_az       = !var.single_nat_gateway
  enable_dns_hostnames         = true
  enable_dns_support           = true
  map_public_ip_on_launch      = false

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
    "karpenter.sh/discovery"          = "${local.name}-primary"
  }
}

module "dr_vpc" {
  count     = local.enable_dr_runtime ? 1 : 0
  providers = { aws = aws.dr }
  source    = "terraform-aws-modules/vpc/aws"
  version   = "~> 6.0"

  name = "${local.name}-dr"
  cidr = var.dr_vpc_cidr
  azs  = var.dr_azs

  public_subnets   = var.dr_public_subnets
  private_subnets  = var.dr_private_subnets
  database_subnets = var.dr_database_subnets

  create_database_subnet_group = true
  enable_nat_gateway           = true
  single_nat_gateway           = var.single_nat_gateway
  one_nat_gateway_per_az       = !var.single_nat_gateway
  enable_dns_hostnames         = true
  enable_dns_support           = true
  map_public_ip_on_launch      = false

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
    "karpenter.sh/discovery"          = "${local.name}-dr"
  }
}
