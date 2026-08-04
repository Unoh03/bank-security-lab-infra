data "aws_ec2_managed_prefix_list" "cloudfront" {
  provider = aws.primary
  name     = "com.amazonaws.global.cloudfront.origin-facing"
}

resource "aws_security_group" "primary_alb" {
  provider    = aws.primary
  name_prefix = "${local.name}-alb-"
  description = "Public ALB reachable from CloudFront"
  vpc_id      = module.primary_vpc.vpc_id
  ingress {
    description     = "HTTP from CloudFront"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.cloudfront.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "dr_alb" {
  count       = local.enable_dr_runtime ? 1 : 0
  provider    = aws.dr
  name_prefix = "${local.name}-dr-alb-"
  description = "DR public ALB"
  vpc_id      = module.dr_vpc[0].vpc_id
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "primary_alb_to_web_nodes" {
  provider = aws.primary

  description                  = "Primary ALB to Kubernetes web Pods on node ENIs"
  security_group_id            = module.primary_eks.node_security_group_id
  referenced_security_group_id = aws_security_group.primary_alb.id
  from_port                    = var.web_service_port
  to_port                      = var.web_service_port
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "dr_alb_to_web_nodes" {
  count    = local.enable_dr_runtime ? 1 : 0
  provider = aws.dr

  description                  = "DR ALB to Kubernetes web Pods on node ENIs"
  security_group_id            = module.dr_eks[0].node_security_group_id
  referenced_security_group_id = aws_security_group.dr_alb[0].id
  from_port                    = var.web_service_port
  to_port                      = var.web_service_port
  ip_protocol                  = "tcp"
}

resource "aws_security_group" "primary_data" {
  provider    = aws.primary
  name_prefix = "${local.name}-data-"
  description = "Primary RDS and Valkey"
  vpc_id      = module.primary_vpc.vpc_id
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [var.primary_vpc_cidr]
  }
  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [var.primary_vpc_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "dr_data" {
  count       = local.enable_dr_runtime ? 1 : 0
  provider    = aws.dr
  name_prefix = "${local.name}-dr-data-"
  description = "DR RDS and Valkey"
  vpc_id      = module.dr_vpc[0].vpc_id
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [var.dr_vpc_cidr]
  }
  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [var.dr_vpc_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle { create_before_destroy = true }
}
