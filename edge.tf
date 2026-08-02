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
  count              = var.enable_dr_compute ? 1 : 0
  provider           = aws.dr
  name               = substr("${local.name}-dr", 0, 32)
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.dr_alb[0].id]
  subnets            = module.dr_vpc.public_subnets
}

resource "aws_lb_target_group" "dr" {
  count       = var.enable_dr_compute ? 1 : 0
  provider    = aws.dr
  name_prefix = "app-"
  port        = var.web_service_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = module.dr_vpc.vpc_id

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
  count             = var.enable_dr_compute ? 1 : 0
  provider          = aws.dr
  load_balancer_arn = aws_lb.dr[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.dr[0].arn
  }
}

# AWS Shield Standard automatically protects Route 53 hosted zones at no additional charge.
resource "aws_route53_zone" "this" {
  count    = var.domain_name != "" && var.create_route53_zone ? 1 : 0
  provider = aws.primary
  name     = var.domain_name
}

# Existing Route 53 hosted zones also receive automatic AWS Shield Standard protection.
data "aws_route53_zone" "existing" {
  count        = var.domain_name != "" && !var.create_route53_zone ? 1 : 0
  provider     = aws.primary
  name         = var.domain_name
  private_zone = false
}

locals {
  route53_zone_id = var.domain_name == "" ? null : (
    var.create_route53_zone ? aws_route53_zone.this[0].zone_id : data.aws_route53_zone.existing[0].zone_id
  )
}

resource "aws_acm_certificate" "cloudfront" {
  count             = var.domain_name == "" ? 0 : 1
  provider          = aws.global
  domain_name       = var.domain_name
  validation_method = "DNS"
  lifecycle { create_before_destroy = true }
}

resource "aws_route53_record" "certificate" {
  for_each = var.domain_name == "" ? {} : {
    for option in aws_acm_certificate.cloudfront[0].domain_validation_options : option.domain_name => {
      name   = option.resource_record_name
      record = option.resource_record_value
      type   = option.resource_record_type
    }
  }
  provider = aws.primary
  zone_id  = local.route53_zone_id
  name     = each.value.name
  type     = each.value.type
  records  = [each.value.record]
  ttl      = 60

  # Reuse/replace an ACM validation CNAME left by an earlier certificate.
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "cloudfront" {
  count                   = var.domain_name == "" ? 0 : 1
  provider                = aws.global
  certificate_arn         = aws_acm_certificate.cloudfront[0].arn
  validation_record_fqdns = [for record in aws_route53_record.certificate : record.fqdn]
}

# AWS Shield Standard automatically protects CloudFront distributions at no additional charge.
resource "aws_cloudfront_distribution" "this" {
  provider   = aws.global
  enabled    = true
  aliases    = var.domain_name == "" ? [] : [var.domain_name]
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
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD", "OPTIONS"]
    compress               = true
    forwarded_values {
      query_string = true
      cookies { forward = "all" }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  viewer_certificate {
    cloudfront_default_certificate = var.domain_name == ""
    acm_certificate_arn            = var.domain_name == "" ? null : aws_acm_certificate_validation.cloudfront[0].certificate_arn
    ssl_support_method             = var.domain_name == "" ? null : "sni-only"
    minimum_protocol_version       = var.domain_name == "" ? "TLSv1" : "TLSv1.2_2021"
  }
}

resource "aws_route53_record" "app" {
  count    = var.domain_name == "" ? 0 : 1
  provider = aws.primary
  zone_id  = local.route53_zone_id
  name     = var.domain_name
  type     = "A"

  # Adopt/replace an existing apex A record with the CloudFront alias.
  allow_overwrite = true

  alias {
    name                   = aws_cloudfront_distribution.this.domain_name
    zone_id                = aws_cloudfront_distribution.this.hosted_zone_id
    evaluate_target_health = false
  }
}
