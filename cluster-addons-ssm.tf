locals {
  primary_cluster_addons_script = templatefile("${path.module}/templates/install-cluster-addons.sh.tpl", {
    region                   = var.primary_region
    cluster_name             = module.primary_eks.cluster_name
    cluster_endpoint         = module.primary_eks.cluster_endpoint
    vpc_id                   = module.primary_vpc.vpc_id
    karpenter_chart_version  = var.karpenter_chart_version
    karpenter_node_role      = module.primary_karpenter.node_iam_role_name
    interruption_queue       = module.primary_karpenter.queue_name
    capacity_types           = jsonencode(var.karpenter_capacity_types)
    cpu_limit                = var.karpenter_cpu_limit
    enable_external_dns      = var.domain_name != "" ? "true" : "false"
    domain_name              = var.domain_name
    web_namespace            = var.web_namespace
    web_service_name         = var.web_service_name
    web_service_port         = var.web_service_port
    target_group_arn         = aws_lb_target_group.primary.arn
    enable_argocd            = var.enable_argocd ? "true" : "false"
    argocd_chart_version     = var.argocd_chart_version
    enable_fluent_bit        = var.enable_dvwa_log_collection ? "true" : "false"
    fluent_bit_chart_version = var.aws_for_fluent_bit_chart_version
    fluent_bit_log_group     = local.security_log_group_names.dvwa
  })

  dr_cluster_addons_script = var.enable_dr_compute ? templatefile("${path.module}/templates/install-cluster-addons.sh.tpl", {
    region                   = var.dr_region
    cluster_name             = module.dr_eks[0].cluster_name
    cluster_endpoint         = module.dr_eks[0].cluster_endpoint
    vpc_id                   = module.dr_vpc.vpc_id
    karpenter_chart_version  = var.karpenter_chart_version
    karpenter_node_role      = module.dr_karpenter[0].node_iam_role_name
    interruption_queue       = module.dr_karpenter[0].queue_name
    capacity_types           = jsonencode(var.karpenter_capacity_types)
    cpu_limit                = var.karpenter_cpu_limit
    enable_external_dns      = var.enable_dr_external_dns && var.domain_name != "" ? "true" : "false"
    domain_name              = var.domain_name
    web_namespace            = var.web_namespace
    web_service_name         = var.web_service_name
    web_service_port         = var.web_service_port
    target_group_arn         = aws_lb_target_group.dr[0].arn
    enable_argocd            = var.enable_dr_argocd ? "true" : "false"
    argocd_chart_version     = var.argocd_chart_version
    enable_fluent_bit        = var.enable_dvwa_log_collection ? "true" : "false"
    fluent_bit_chart_version = var.aws_for_fluent_bit_chart_version
    fluent_bit_log_group     = local.security_log_group_names.dvwa_dr
  }) : ""
}

resource "aws_ssm_document" "primary_cluster_addons" {
  provider = aws.primary
  # Customer-owned SSM document names cannot begin with the reserved "aws" prefix.
  name            = "custom-${local.name}-primary-cluster-addons"
  document_type   = "Command"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Install and reconcile EKS cluster add-ons from the regional bastion"
    mainSteps = [{
      action = "aws:runShellScript"
      name   = "installClusterAddons"
      inputs = {
        timeoutSeconds = "1800"
        runCommand     = [local.primary_cluster_addons_script]
      }
    }]
  })
}

resource "aws_ssm_association" "primary_cluster_addons" {
  provider                         = aws.primary
  name                             = aws_ssm_document.primary_cluster_addons.name
  document_version                 = aws_ssm_document.primary_cluster_addons.document_version
  association_name                 = "${local.name}-primary-cluster-addons"
  wait_for_success_timeout_seconds = 1800

  targets {
    key    = "InstanceIds"
    values = [aws_instance.primary_bastion.id]
  }

  depends_on = [
    module.primary_karpenter,
    module.primary_aws_lb_controller_pod_identity,
    module.primary_external_dns_pod_identity,
    aws_eks_pod_identity_association.primary_web_s3,
    aws_eks_pod_identity_association.primary_dvwa_log_forwarder
  ]
}

resource "aws_ssm_document" "dr_cluster_addons" {
  count           = var.enable_dr_compute ? 1 : 0
  provider        = aws.dr
  name            = "custom-${local.name}-dr-cluster-addons"
  document_type   = "Command"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Install and reconcile DR EKS cluster add-ons from the regional bastion"
    mainSteps = [{
      action = "aws:runShellScript"
      name   = "installClusterAddons"
      inputs = {
        timeoutSeconds = "1800"
        runCommand     = [local.dr_cluster_addons_script]
      }
    }]
  })
}

resource "aws_ssm_association" "dr_cluster_addons" {
  count                            = var.enable_dr_compute ? 1 : 0
  provider                         = aws.dr
  name                             = aws_ssm_document.dr_cluster_addons[0].name
  document_version                 = aws_ssm_document.dr_cluster_addons[0].document_version
  association_name                 = "${local.name}-dr-cluster-addons"
  wait_for_success_timeout_seconds = 1800

  targets {
    key    = "InstanceIds"
    values = [aws_instance.dr_bastion[0].id]
  }

  depends_on = [
    module.dr_karpenter,
    module.dr_aws_lb_controller_pod_identity,
    module.dr_external_dns_pod_identity,
    aws_eks_pod_identity_association.dr_web_s3,
    aws_eks_pod_identity_association.dr_dvwa_log_forwarder
  ]
}
