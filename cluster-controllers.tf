module "primary_aws_lb_controller_pod_identity" {
  providers = { aws = aws.primary }
  source    = "terraform-aws-modules/eks-pod-identity/aws"
  version   = "~> 2.0"

  name                            = "${local.name}-primary-aws-lbc"
  attach_aws_lb_controller_policy = true

  associations = {
    controller = {
      cluster_name    = module.primary_eks.cluster_name
      namespace       = "kube-system"
      service_account = "aws-load-balancer-controller"
    }
  }
}

module "dr_aws_lb_controller_pod_identity" {
  count     = local.enable_dr_runtime ? 1 : 0
  providers = { aws = aws.dr }
  source    = "terraform-aws-modules/eks-pod-identity/aws"
  version   = "~> 2.0"

  name                            = "${local.name}-dr-aws-lbc"
  attach_aws_lb_controller_policy = true

  associations = {
    controller = {
      cluster_name    = module.dr_eks[0].cluster_name
      namespace       = "kube-system"
      service_account = "aws-load-balancer-controller"
    }
  }
}

resource "helm_release" "primary_aws_load_balancer_controller" {
  count    = var.manage_addons_via_local_helm ? 1 : 0
  provider = helm.primary

  name       = "aws-load-balancer-controller"
  namespace  = "kube-system"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  wait       = true
  timeout    = 600

  values = [yamlencode({
    clusterName = module.primary_eks.cluster_name
    region      = var.primary_region
    vpcId       = module.primary_vpc.vpc_id
    nodeSelector = {
      workload = "system"
    }
    serviceAccount = {
      create = true
      name   = "aws-load-balancer-controller"
    }
  })]

  depends_on = [module.primary_aws_lb_controller_pod_identity]
}

resource "helm_release" "dr_aws_load_balancer_controller" {
  count    = local.enable_dr_runtime && var.manage_addons_via_local_helm ? 1 : 0
  provider = helm.dr

  name       = "aws-load-balancer-controller"
  namespace  = "kube-system"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  wait       = true
  timeout    = 600

  values = [yamlencode({
    clusterName = module.dr_eks[0].cluster_name
    region      = var.dr_region
    vpcId       = module.dr_vpc[0].vpc_id
    nodeSelector = {
      workload = "system"
    }
    serviceAccount = {
      create = true
      name   = "aws-load-balancer-controller"
    }
  })]

  # Serialize identical chart downloads on Windows and deploy primary first.
  depends_on = [
    module.dr_aws_lb_controller_pod_identity,
    helm_release.primary_aws_load_balancer_controller
  ]
}

module "primary_external_dns_pod_identity" {
  count     = local.domain_name != "" ? 1 : 0
  providers = { aws = aws.primary }
  source    = "terraform-aws-modules/eks-pod-identity/aws"
  version   = "~> 2.0"

  name                       = "${local.name}-primary-external-dns"
  attach_external_dns_policy = true
  external_dns_hosted_zone_arns = [
    "arn:aws:route53:::hostedzone/${local.route53_zone_id}"
  ]

  associations = {
    external_dns = {
      cluster_name    = module.primary_eks.cluster_name
      namespace       = "external-dns"
      service_account = "external-dns"
    }
  }
}

module "dr_external_dns_pod_identity" {
  count     = local.enable_dr_runtime && var.enable_dr_external_dns && local.domain_name != "" ? 1 : 0
  providers = { aws = aws.dr }
  source    = "terraform-aws-modules/eks-pod-identity/aws"
  version   = "~> 2.0"

  name                       = "${local.name}-dr-external-dns"
  attach_external_dns_policy = true
  external_dns_hosted_zone_arns = [
    "arn:aws:route53:::hostedzone/${local.route53_zone_id}"
  ]

  associations = {
    external_dns = {
      cluster_name    = module.dr_eks[0].cluster_name
      namespace       = "external-dns"
      service_account = "external-dns"
    }
  }
}

resource "helm_release" "primary_external_dns" {
  count    = local.domain_name != "" && var.manage_addons_via_local_helm ? 1 : 0
  provider = helm.primary

  name             = "external-dns"
  namespace        = "external-dns"
  create_namespace = true
  repository       = "https://kubernetes-sigs.github.io/external-dns/"
  chart            = "external-dns"
  wait             = true
  timeout          = 600

  values = [yamlencode({
    provider      = { name = "aws" }
    policy        = "upsert-only"
    domainFilters = [local.domain_name]
    txtOwnerId    = module.primary_eks.cluster_name
    nodeSelector  = { workload = "system" }
    serviceAccount = {
      create = true
      name   = "external-dns"
    }
  })]

  depends_on = [module.primary_external_dns_pod_identity]
}

resource "helm_release" "dr_external_dns" {
  count    = local.enable_dr_runtime && var.enable_dr_external_dns && local.domain_name != "" && var.manage_addons_via_local_helm ? 1 : 0
  provider = helm.dr

  name             = "external-dns"
  namespace        = "external-dns"
  create_namespace = true
  repository       = "https://kubernetes-sigs.github.io/external-dns/"
  chart            = "external-dns"
  wait             = true
  timeout          = 600

  values = [yamlencode({
    provider      = { name = "aws" }
    policy        = "upsert-only"
    domainFilters = [local.domain_name]
    txtOwnerId    = module.dr_eks[0].cluster_name
    nodeSelector  = { workload = "system" }
    serviceAccount = {
      create = true
      name   = "external-dns"
    }
  })]

  # Serialize identical chart downloads on Windows and deploy primary first.
  depends_on = [
    module.dr_external_dns_pod_identity,
    helm_release.primary_external_dns
  ]
}
