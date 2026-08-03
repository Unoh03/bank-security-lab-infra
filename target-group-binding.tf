resource "helm_release" "primary_web_target_group_binding" {
  count    = var.manage_addons_via_local_helm ? 1 : 0
  provider = helm.primary

  name             = "web-target-group-binding"
  namespace        = var.web_namespace
  create_namespace = true
  chart            = "${path.module}/charts/target-group-binding"
  wait             = true
  timeout          = 300

  values = [yamlencode({
    name           = "web"
    serviceName    = var.web_service_name
    servicePort    = var.web_service_port
    targetGroupARN = aws_lb_target_group.primary.arn
    vpcID          = module.primary_vpc.vpc_id
  })]

  depends_on = [helm_release.primary_aws_load_balancer_controller]
}

resource "helm_release" "dr_web_target_group_binding" {
  count    = local.enable_dr_runtime && var.manage_addons_via_local_helm ? 1 : 0
  provider = helm.dr

  name             = "web-target-group-binding"
  namespace        = var.web_namespace
  create_namespace = true
  chart            = "${path.module}/charts/target-group-binding"
  wait             = true
  timeout          = 300

  values = [yamlencode({
    name           = "web"
    serviceName    = var.web_service_name
    servicePort    = var.web_service_port
    targetGroupARN = aws_lb_target_group.dr[0].arn
    vpcID          = module.dr_vpc[0].vpc_id
  })]

  depends_on = [
    helm_release.dr_aws_load_balancer_controller,
    helm_release.primary_web_target_group_binding
  ]
}
