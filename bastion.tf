data "aws_ssm_parameter" "primary_al2023_ami" {
  provider = aws.primary
  name     = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_ssm_parameter" "dr_al2023_ami" {
  provider = aws.dr
  name     = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_key_pair" "primary_bastion" {
  provider = aws.primary
  key_name = var.primary_bastion_key_pair_name
}

data "aws_key_pair" "dr_bastion" {
  count    = var.enable_dr_compute ? 1 : 0
  provider = aws.dr
  key_name = var.dr_bastion_key_pair_name
}

data "aws_iam_policy_document" "bastion_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "primary_bastion" {
  provider           = aws.primary
  name               = "${local.name}-primary-bastion"
  assume_role_policy = data.aws_iam_policy_document.bastion_assume_role.json
}

resource "aws_iam_role_policy_attachment" "primary_bastion_ssm" {
  provider   = aws.primary
  role       = aws_iam_role.primary_bastion.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "primary_bastion_eks_describe" {
  provider = aws.primary
  role     = aws_iam_role.primary_bastion.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["eks:DescribeCluster"]
      Resource = module.primary_eks.cluster_arn
    }]
  })
}

resource "aws_iam_instance_profile" "primary_bastion" {
  provider = aws.primary
  name     = "${local.name}-primary-bastion"
  role     = aws_iam_role.primary_bastion.name
}

resource "aws_security_group" "primary_bastion" {
  provider    = aws.primary
  name_prefix = "${local.name}-primary-bastion-"
  description = "SSM-only bastion; no inbound access"
  vpc_id      = module.primary_vpc.vpc_id

  dynamic "ingress" {
    for_each = length(var.bastion_ssh_cidrs) == 0 ? [] : [1]
    content {
      description = "SSH administration"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.bastion_ssh_cidrs
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle { create_before_destroy = true }
}

resource "aws_instance" "primary_bastion" {
  provider                    = aws.primary
  ami                         = data.aws_ssm_parameter.primary_al2023_ami.value
  instance_type               = var.bastion_instance_type
  subnet_id                   = module.primary_vpc.public_subnets[0]
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.primary_bastion.id]
  iam_instance_profile        = aws_iam_instance_profile.primary_bastion.name
  key_name                    = data.aws_key_pair.primary_bastion.key_name
  user_data = templatefile("${path.module}/templates/bastion-userdata.sh.tpl", {
    region             = var.primary_region
    cluster_name       = module.primary_eks.cluster_name
    kubernetes_version = var.kubernetes_version
    helm_version       = var.helm_cli_version
  })
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 16
  }

  tags = { Name = "${local.name}-primary-bastion" }

  depends_on = [aws_iam_role_policy.primary_bastion_eks_describe]
}

resource "aws_iam_role" "dr_bastion" {
  count              = var.enable_dr_compute ? 1 : 0
  provider           = aws.dr
  name               = "${local.name}-dr-bastion"
  assume_role_policy = data.aws_iam_policy_document.bastion_assume_role.json
}

resource "aws_iam_role_policy_attachment" "dr_bastion_ssm" {
  count      = var.enable_dr_compute ? 1 : 0
  provider   = aws.dr
  role       = aws_iam_role.dr_bastion[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "dr_bastion_eks_describe" {
  count    = var.enable_dr_compute ? 1 : 0
  provider = aws.dr
  role     = aws_iam_role.dr_bastion[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["eks:DescribeCluster"]
      Resource = module.dr_eks[0].cluster_arn
    }]
  })
}

resource "aws_iam_instance_profile" "dr_bastion" {
  count    = var.enable_dr_compute ? 1 : 0
  provider = aws.dr
  name     = "${local.name}-dr-bastion"
  role     = aws_iam_role.dr_bastion[0].name
}

resource "aws_security_group" "dr_bastion" {
  count       = var.enable_dr_compute ? 1 : 0
  provider    = aws.dr
  name_prefix = "${local.name}-dr-bastion-"
  description = "SSM-only DR bastion; no inbound access"
  vpc_id      = module.dr_vpc.vpc_id

  dynamic "ingress" {
    for_each = length(var.bastion_ssh_cidrs) == 0 ? [] : [1]
    content {
      description = "SSH administration"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.bastion_ssh_cidrs
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle { create_before_destroy = true }
}

resource "aws_instance" "dr_bastion" {
  count                       = var.enable_dr_compute ? 1 : 0
  provider                    = aws.dr
  ami                         = data.aws_ssm_parameter.dr_al2023_ami.value
  instance_type               = var.bastion_instance_type
  subnet_id                   = module.dr_vpc.public_subnets[0]
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.dr_bastion[0].id]
  iam_instance_profile        = aws_iam_instance_profile.dr_bastion[0].name
  key_name                    = data.aws_key_pair.dr_bastion[0].key_name
  user_data = templatefile("${path.module}/templates/bastion-userdata.sh.tpl", {
    region             = var.dr_region
    cluster_name       = module.dr_eks[0].cluster_name
    kubernetes_version = var.kubernetes_version
    helm_version       = var.helm_cli_version
  })
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 16
  }

  tags = { Name = "${local.name}-dr-bastion" }

  depends_on = [aws_iam_role_policy.dr_bastion_eks_describe]
}
