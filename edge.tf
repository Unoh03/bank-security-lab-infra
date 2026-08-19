# AWS Shield Standard automatically protects internet-facing ALBs at no additional charge.
resource "aws_lb" "primary" {
  provider           = aws.primary
  name               = substr("${local.name}-primary", 0, 32)
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.primary_alb.id]
  subnets            = module.primary_vpc.public_subnets

  dynamic "access_logs" {
    for_each = var.enable_edge_access_logging ? [1] : []
    content {
      bucket  = local.security_log_bucket_name
      prefix  = "alb/primary"
      enabled = true
    }
  }
}

resource "aws_lb_target_group" "primary" {
  provider    = aws.primary
  name_prefix = "app-"
  port        = var.web_service_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = module.primary_vpc.vpc_id

  health_check {
    path    = var.web_health_check_path
    matcher = "200-399"
  }
  tags = {
    "eks:eks-cluster-name" = module.primary_eks.cluster_name
  }
  lifecycle { create_before_destroy = true }
}

resource "aws_lb_listener" "primary" {
  provider          = aws.primary
  load_balancer_arn = aws_lb.primary.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.primary.arn
  }
}

# AWS Shield Standard automatically protects internet-facing ALBs at no additional charge.
resource "aws_lb" "dr" {
  count              = local.enable_dr_runtime ? 1 : 0
  provider           = aws.dr
  name               = substr("${local.name}-dr", 0, 32)
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.dr_alb[0].id]
  subnets            = module.dr_vpc[0].public_subnets
}

resource "aws_lb_target_group" "dr" {
  count       = local.enable_dr_runtime ? 1 : 0
  provider    = aws.dr
  name_prefix = "app-"
  port        = var.web_service_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = module.dr_vpc[0].vpc_id

  health_check {
    path    = var.web_health_check_path
    matcher = "200-399"
  }

  tags = {
    "eks:eks-cluster-name" = module.dr_eks[0].cluster_name
  }

  lifecycle { create_before_destroy = true }
}

resource "aws_lb_listener" "dr" {
  count             = local.enable_dr_runtime ? 1 : 0
  provider          = aws.dr
  load_balancer_arn = aws_lb.dr[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.dr[0].arn
  }
}

locals {
  foundation_contract_version    = try(data.terraform_remote_state.foundation.outputs.foundation_contract_version, 0)
  domain_name                    = try(data.terraform_remote_state.foundation.outputs.domain_name, "")
  route53_zone_id                = try(data.terraform_remote_state.foundation.outputs.route53_zone_id, null)
  cloudfront_acm_certificate_arn = try(data.terraform_remote_state.foundation.outputs.cloudfront_acm_certificate_arn, null)
}

check "foundation_domain_contract" {
  assert {
    condition = (
      local.foundation_contract_version >= 2 &&
      (
        local.domain_name == "" ||
        (
          try(trimspace(local.route53_zone_id), "") != "" &&
          try(trimspace(local.cloudfront_acm_certificate_arn), "") != ""
        )
      )
    )
    error_message = "Apply Foundation contract v2 before Daily Runtime; a configured domain must include Route 53 zone ID and CloudFront ACM certificate ARN."
  }
}

# AWS Shield Standard automatically protects CloudFront distributions at no additional charge.
resource "aws_cloudfront_distribution" "this" {
  provider   = aws.global
  enabled    = true
  aliases    = local.domain_name == "" ? [] : [local.domain_name]
  web_acl_id = var.enable_waf_observation ? aws_wafv2_web_acl.edge[0].arn : null

  origin {
    domain_name = aws_lb.primary.dns_name
    origin_id   = "primary-alb"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "primary-alb"
    viewer_protocol_policy = var.enable_https_redirect ? "redirect-to-https" : "allow-all"
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD", "OPTIONS"]
    compress               = true
    forwarded_values {
      query_string = true
      headers      = ["X-SOC-TAKE-ID"]
      cookies { forward = "all" }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  viewer_certificate {
    cloudfront_default_certificate = local.domain_name == ""
    acm_certificate_arn            = local.domain_name == "" ? null : local.cloudfront_acm_certificate_arn
    ssl_support_method             = local.domain_name == "" ? null : "sni-only"
    minimum_protocol_version       = local.domain_name == "" ? "TLSv1" : "TLSv1.2_2021"
  }
}

resource "aws_route53_record" "app" {
  count    = local.domain_name == "" ? 0 : 1
  provider = aws.primary
  zone_id  = local.route53_zone_id
  name     = local.domain_name
  type     = "A"

  # Adopt/replace an existing apex A record with the CloudFront alias.
  allow_overwrite = true

  alias {
    name                   = aws_cloudfront_distribution.this.domain_name
    zone_id                = aws_cloudfront_distribution.this.hosted_zone_id
    evaluate_target_health = false
  }
}
