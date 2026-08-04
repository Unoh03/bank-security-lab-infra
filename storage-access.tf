data "aws_iam_policy_document" "pod_identity_assume_role" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "primary_efs_csi" {
  count              = var.enable_efs ? 1 : 0
  provider           = aws.primary
  name               = "${local.name}-primary-efs-csi"
  assume_role_policy = data.aws_iam_policy_document.pod_identity_assume_role.json
}

resource "aws_iam_role_policy_attachment" "primary_efs_csi" {
  count      = var.enable_efs ? 1 : 0
  provider   = aws.primary
  role       = aws_iam_role.primary_efs_csi[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEFSCSIDriverPolicy"
}

resource "aws_iam_role" "dr_efs_csi" {
  count              = local.enable_dr_runtime && var.enable_efs ? 1 : 0
  provider           = aws.dr
  name               = "${local.name}-dr-efs-csi"
  assume_role_policy = data.aws_iam_policy_document.pod_identity_assume_role.json
}

resource "aws_iam_role_policy_attachment" "dr_efs_csi" {
  count      = local.enable_dr_runtime && var.enable_efs ? 1 : 0
  provider   = aws.dr
  role       = aws_iam_role.dr_efs_csi[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEFSCSIDriverPolicy"
}

resource "aws_security_group" "primary_efs" {
  count       = var.enable_efs ? 1 : 0
  provider    = aws.primary
  name_prefix = "${local.name}-primary-efs-"
  description = "NFS from primary EKS nodes"
  vpc_id      = module.primary_vpc.vpc_id

  ingress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [module.primary_eks.node_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle { create_before_destroy = true }
}

resource "aws_efs_file_system" "primary" {
  count          = var.enable_efs ? 1 : 0
  provider       = aws.primary
  encrypted      = true
  creation_token = "${local.name}-primary"
  tags           = { Name = "${local.name}-primary" }
}

resource "aws_efs_mount_target" "primary" {
  provider = aws.primary
  for_each = var.enable_efs ? {
    for index, cidr in var.primary_private_subnets : tostring(index) => module.primary_vpc.private_subnets[index]
  } : {}
  file_system_id  = aws_efs_file_system.primary[0].id
  subnet_id       = each.value
  security_groups = [aws_security_group.primary_efs[0].id]
}

resource "aws_security_group" "dr_efs" {
  count       = local.enable_dr_runtime && var.enable_efs ? 1 : 0
  provider    = aws.dr
  name_prefix = "${local.name}-dr-efs-"
  description = "NFS from DR EKS nodes"
  vpc_id      = module.dr_vpc[0].vpc_id

  ingress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [module.dr_eks[0].node_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle { create_before_destroy = true }
}

resource "aws_efs_file_system" "dr" {
  count          = local.enable_dr_runtime && var.enable_efs ? 1 : 0
  provider       = aws.dr
  encrypted      = true
  creation_token = "${local.name}-dr"
  tags           = { Name = "${local.name}-dr" }
}

resource "aws_efs_mount_target" "dr" {
  provider = aws.dr
  for_each = local.enable_dr_runtime && var.enable_efs ? {
    for index, cidr in var.dr_private_subnets : tostring(index) => module.dr_vpc[0].private_subnets[index]
  } : {}
  file_system_id  = aws_efs_file_system.dr[0].id
  subnet_id       = each.value
  security_groups = [aws_security_group.dr_efs[0].id]
}

resource "aws_iam_role" "primary_web_s3" {
  count              = var.enable_web_s3_pod_identity ? 1 : 0
  provider           = aws.primary
  name               = "${local.name}-primary-web-s3"
  assume_role_policy = data.aws_iam_policy_document.pod_identity_assume_role.json
}

resource "aws_iam_role_policy" "primary_web_s3" {
  count    = var.enable_web_s3_pod_identity ? 1 : 0
  provider = aws.primary
  role     = aws_iam_role.primary_web_s3[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:ListBucket", "s3:GetBucketLocation"], Resource = aws_s3_bucket.primary.arn },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Resource = "${aws_s3_bucket.primary.arn}/web/*" }
    ]
  })
}

resource "aws_eks_pod_identity_association" "primary_web_s3" {
  count           = var.enable_web_s3_pod_identity ? 1 : 0
  provider        = aws.primary
  cluster_name    = module.primary_eks.cluster_name
  namespace       = var.web_namespace
  service_account = var.web_service_account
  role_arn        = aws_iam_role.primary_web_s3[0].arn
}

resource "aws_iam_role" "dr_web_s3" {
  count              = var.enable_web_s3_pod_identity && local.enable_dr_runtime ? 1 : 0
  provider           = aws.dr
  name               = "${local.name}-dr-web-s3"
  assume_role_policy = data.aws_iam_policy_document.pod_identity_assume_role.json
}

resource "aws_iam_role_policy" "dr_web_s3" {
  count    = var.enable_web_s3_pod_identity && local.enable_dr_runtime ? 1 : 0
  provider = aws.dr
  role     = aws_iam_role.dr_web_s3[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:ListBucket", "s3:GetBucketLocation"], Resource = aws_s3_bucket.dr[0].arn },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Resource = "${aws_s3_bucket.dr[0].arn}/web/*" }
    ]
  })
}

resource "aws_eks_pod_identity_association" "dr_web_s3" {
  count           = var.enable_web_s3_pod_identity && local.enable_dr_runtime ? 1 : 0
  provider        = aws.dr
  cluster_name    = module.dr_eks[0].cluster_name
  namespace       = var.web_namespace
  service_account = var.web_service_account
  role_arn        = aws_iam_role.dr_web_s3[0].arn
}
