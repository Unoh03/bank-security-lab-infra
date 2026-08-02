module "primary_eks" {
  providers = { aws = aws.primary }
  source    = "terraform-aws-modules/eks/aws"
  version   = "~> 21.0"

  name               = "${local.name}-primary"
  kubernetes_version = var.kubernetes_version
  vpc_id             = module.primary_vpc.vpc_id
  subnet_ids         = module.primary_vpc.private_subnets

  endpoint_private_access                  = true
  endpoint_public_access                   = false
  enable_cluster_creator_admin_permissions = true
  enabled_log_types                        = ["api", "audit", "authenticator"]
  create_cloudwatch_log_group              = false

  access_entries = {
    bastion = {
      principal_arn = aws_iam_role.primary_bastion.arn
      policy_associations = {
        cluster_admin = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = {
            type = "cluster"
          }
        }
      }
    }
  }

  security_group_additional_rules = {
    bastion_https = {
      description              = "EKS API access from the primary SSM bastion"
      protocol                 = "tcp"
      from_port                = 443
      to_port                  = 443
      type                     = "ingress"
      source_security_group_id = aws_security_group.primary_bastion.id
    }
  }

  node_security_group_tags = {
    "karpenter.sh/discovery" = "${local.name}-primary"
  }

  addons = {
    coredns                = {}
    kube-proxy             = {}
    vpc-cni                = { before_compute = true }
    eks-pod-identity-agent = { before_compute = true }
    aws-efs-csi-driver = {
      most_recent = true
      pod_identity_association = [{
        role_arn        = aws_iam_role.primary_efs_csi.arn
        service_account = "efs-csi-controller-sa"
      }]
    }
  }

  eks_managed_node_groups = {
    system = {
      instance_types = var.node_instance_types
      min_size       = 2
      max_size       = 4
      desired_size   = 2
      labels         = { workload = "system" }
    }
  }
}

module "dr_eks" {
  count     = var.enable_dr_compute ? 1 : 0
  providers = { aws = aws.dr }
  source    = "terraform-aws-modules/eks/aws"
  version   = "~> 21.0"

  name               = "${local.name}-dr"
  kubernetes_version = var.kubernetes_version
  vpc_id             = module.dr_vpc.vpc_id
  subnet_ids         = module.dr_vpc.private_subnets

  endpoint_private_access                  = true
  endpoint_public_access                   = false
  enable_cluster_creator_admin_permissions = true
  enabled_log_types                        = ["api", "audit", "authenticator"]

  access_entries = {
    bastion = {
      principal_arn = aws_iam_role.dr_bastion[0].arn
      policy_associations = {
        cluster_admin = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = {
            type = "cluster"
          }
        }
      }
    }
  }

  security_group_additional_rules = {
    bastion_https = {
      description              = "EKS API access from the DR SSM bastion"
      protocol                 = "tcp"
      from_port                = 443
      to_port                  = 443
      type                     = "ingress"
      source_security_group_id = aws_security_group.dr_bastion[0].id
    }
  }

  node_security_group_tags = {
    "karpenter.sh/discovery" = "${local.name}-dr"
  }

  addons = {
    coredns                = {}
    kube-proxy             = {}
    vpc-cni                = { before_compute = true }
    eks-pod-identity-agent = { before_compute = true }
    aws-efs-csi-driver = {
      most_recent = true
      pod_identity_association = [{
        role_arn        = aws_iam_role.dr_efs_csi.arn
        service_account = "efs-csi-controller-sa"
      }]
    }
  }

  eks_managed_node_groups = {
    system = {
      instance_types = var.node_instance_types
      min_size       = 1
      max_size       = 2
      desired_size   = 1
      labels         = { workload = "system" }
    }
  }
}

# Karpenter IAM/infrastructure is prepared for each cluster.
module "primary_karpenter" {
  providers = { aws = aws.primary }
  source    = "terraform-aws-modules/eks/aws//modules/karpenter"
  version   = "~> 21.0"

  cluster_name                    = module.primary_eks.cluster_name
  create_pod_identity_association = true
  enable_inline_policy            = true
  node_iam_role_use_name_prefix   = false
  node_iam_role_name              = "${local.name}-primary-karpenter-node"
}

module "dr_karpenter" {
  count     = var.enable_dr_compute ? 1 : 0
  providers = { aws = aws.dr }
  source    = "terraform-aws-modules/eks/aws//modules/karpenter"
  version   = "~> 21.0"

  cluster_name                    = module.dr_eks[0].cluster_name
  create_pod_identity_association = true
  enable_inline_policy            = true
  node_iam_role_use_name_prefix   = false
  node_iam_role_name              = "${local.name}-dr-karpenter-node"
}

resource "helm_release" "primary_karpenter" {
  count    = var.manage_addons_via_local_helm ? 1 : 0
  provider = helm.primary

  name       = "karpenter"
  namespace  = "kube-system"
  repository = "oci://public.ecr.aws/karpenter"
  chart      = "karpenter"
  version    = var.karpenter_chart_version
  wait       = true
  timeout    = 600

  values = [yamlencode({
    nodeSelector = {
      "workload" = "system"
    }
    settings = {
      clusterName       = module.primary_eks.cluster_name
      clusterEndpoint   = module.primary_eks.cluster_endpoint
      interruptionQueue = module.primary_karpenter.queue_name
    }
  })]

  depends_on = [module.primary_eks, module.primary_karpenter]
}

resource "helm_release" "dr_karpenter" {
  count    = var.enable_dr_compute && var.manage_addons_via_local_helm ? 1 : 0
  provider = helm.dr

  name       = "karpenter"
  namespace  = "kube-system"
  repository = "oci://public.ecr.aws/karpenter"
  chart      = "karpenter"
  version    = var.karpenter_chart_version
  wait       = true
  timeout    = 600

  values = [yamlencode({
    nodeSelector = {
      "workload" = "system"
    }
    settings = {
      clusterName       = module.dr_eks[0].cluster_name
      clusterEndpoint   = module.dr_eks[0].cluster_endpoint
      interruptionQueue = module.dr_karpenter[0].queue_name
    }
  })]

  depends_on = [module.dr_eks, module.dr_karpenter]
}

resource "helm_release" "primary_karpenter_node_config" {
  count    = var.manage_addons_via_local_helm ? 1 : 0
  provider = helm.primary

  name      = "karpenter-node-config"
  namespace = "kube-system"
  chart     = "${path.module}/charts/karpenter-node-config"

  values = [yamlencode({
    clusterName  = module.primary_eks.cluster_name
    nodeRole     = module.primary_karpenter.node_iam_role_name
    capacityType = var.karpenter_capacity_types
    cpuLimit     = var.karpenter_cpu_limit
  })]

  depends_on = [helm_release.primary_karpenter]
}

resource "helm_release" "dr_karpenter_node_config" {
  count    = var.enable_dr_compute && var.manage_addons_via_local_helm ? 1 : 0
  provider = helm.dr

  name      = "karpenter-node-config"
  namespace = "kube-system"
  chart     = "${path.module}/charts/karpenter-node-config"

  values = [yamlencode({
    clusterName  = module.dr_eks[0].cluster_name
    nodeRole     = module.dr_karpenter[0].node_iam_role_name
    capacityType = var.karpenter_capacity_types
    cpuLimit     = var.karpenter_cpu_limit
  })]

  depends_on = [helm_release.dr_karpenter]
}
