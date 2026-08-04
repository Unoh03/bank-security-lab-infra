# The authoritative hosted zone is external, persistent infrastructure. This
# Foundation only discovers it and owns the reusable CloudFront certificate.
data "aws_route53_zone" "existing" {
  count        = var.domain_name == "" ? 0 : 1
  name         = var.domain_name
  private_zone = false
}

resource "aws_acm_certificate" "cloudfront" {
  count             = var.domain_name == "" ? 0 : 1
  provider          = aws.global
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "cloudfront_certificate_validation" {
  for_each = var.domain_name == "" ? {} : {
    for option in aws_acm_certificate.cloudfront[0].domain_validation_options : option.domain_name => {
      name   = option.resource_record_name
      record = option.resource_record_value
      type   = option.resource_record_type
    }
  }

  zone_id         = data.aws_route53_zone.existing[0].zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.record]
  ttl             = 60
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "cloudfront" {
  count                   = var.domain_name == "" ? 0 : 1
  provider                = aws.global
  certificate_arn         = aws_acm_certificate.cloudfront[0].arn
  validation_record_fqdns = [for record in aws_route53_record.cloudfront_certificate_validation : record.fqdn]
}
