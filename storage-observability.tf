resource "aws_s3_bucket" "primary" {
  provider      = aws.primary
  bucket_prefix = "${local.name}-primary-"
  force_destroy = true
}

# The Capital One negative control must use a real, separately named S3
# bucket.  It is created only with the explicitly approved lab profile so the
# default/hardened runtime never gains another data-event target.
locals {
  capital_one_secondary_control_enabled       = local.capital_one_lab_enabled && var.runtime_profile == "minimal"
  capital_one_secondary_control_object_key    = "validation/capital-one-demo.csv"
  capital_one_other_prefix_control_object_key = "other-prefix/capital-one-demo.csv"
  capital_one_secondary_control_csv = format("%s\n", trimspace(<<-CSV
    training_marker,record_id,customer_name,email,account_last4
    FAKE_TRAINING_DATA,CAP-001,Demo Customer 01,demo01@example.invalid,0001
    FAKE_TRAINING_DATA,CAP-002,Demo Customer 02,demo02@example.invalid,0002
    FAKE_TRAINING_DATA,CAP-003,Demo Customer 03,demo03@example.invalid,0003
    FAKE_TRAINING_DATA,CAP-004,Demo Customer 04,demo04@example.invalid,0004
    FAKE_TRAINING_DATA,CAP-005,Demo Customer 05,demo05@example.invalid,0005
  CSV
  ))
}

resource "aws_s3_bucket" "capital_one_secondary_control" {
  count         = local.capital_one_secondary_control_enabled ? 1 : 0
  provider      = aws.primary
  bucket_prefix = "${local.name}-capital-one-secondary-control-"
  # Do not force-delete unexpected objects during Daily teardown.  The
  # managed fixture object is removed by Terraform; an untracked object makes
  # teardown fail closed instead of silently deleting data.
  force_destroy = false
}

resource "aws_s3_bucket_server_side_encryption_configuration" "capital_one_secondary_control" {
  count    = local.capital_one_secondary_control_enabled ? 1 : 0
  provider = aws.primary
  bucket   = aws_s3_bucket.capital_one_secondary_control[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "capital_one_secondary_control" {
  count                   = local.capital_one_secondary_control_enabled ? 1 : 0
  provider                = aws.primary
  bucket                  = aws_s3_bucket.capital_one_secondary_control[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "capital_one_secondary_control" {
  count        = local.capital_one_secondary_control_enabled ? 1 : 0
  provider     = aws.primary
  bucket       = aws_s3_bucket.capital_one_secondary_control[0].id
  key          = local.capital_one_secondary_control_object_key
  content      = local.capital_one_secondary_control_csv
  content_type = "text/csv"

  metadata = {
    training-marker = "FAKE_TRAINING_DATA"
    sha256          = sha256(local.capital_one_secondary_control_csv)
    record-count    = "5"
  }

  depends_on = [aws_s3_bucket_server_side_encryption_configuration.capital_one_secondary_control]
}

resource "aws_s3_object" "capital_one_other_prefix_control" {
  count        = local.capital_one_secondary_control_enabled ? 1 : 0
  provider     = aws.primary
  bucket       = aws_s3_bucket.primary.id
  key          = local.capital_one_other_prefix_control_object_key
  content      = local.capital_one_secondary_control_csv
  content_type = "text/csv"

  metadata = {
    training-marker = "FAKE_TRAINING_DATA"
    sha256          = sha256(local.capital_one_secondary_control_csv)
    record-count    = "5"
  }

  depends_on = [aws_s3_bucket_server_side_encryption_configuration.primary]
}

resource "aws_s3_bucket" "dr" {
  count         = local.enable_dr_runtime ? 1 : 0
  provider      = aws.dr
  bucket_prefix = "${local.name}-dr-"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "primary" {
  provider = aws.primary
  bucket   = aws_s3_bucket.primary.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_versioning" "dr" {
  count    = local.enable_dr_runtime ? 1 : 0
  provider = aws.dr
  bucket   = aws_s3_bucket.dr[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "primary" {
  provider = aws.primary
  bucket   = aws_s3_bucket.primary.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "dr" {
  count    = local.enable_dr_runtime ? 1 : 0
  provider = aws.dr
  bucket   = aws_s3_bucket.dr[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "primary" {
  provider                = aws.primary
  bucket                  = aws_s3_bucket.primary.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "dr" {
  count                   = local.enable_dr_runtime ? 1 : 0
  provider                = aws.dr
  bucket                  = aws_s3_bucket.dr[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_role" "s3_replication" {
  count    = local.enable_dr_runtime ? 1 : 0
  provider = aws.primary
  name     = "${local.name}-s3-replication"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "s3.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "s3_replication" {
  count    = local.enable_dr_runtime ? 1 : 0
  provider = aws.primary
  role     = aws_iam_role.s3_replication[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetReplicationConfiguration", "s3:ListBucket"], Resource = aws_s3_bucket.primary.arn },
      { Effect = "Allow", Action = ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging"], Resource = "${aws_s3_bucket.primary.arn}/*" },
      { Effect = "Allow", Action = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"], Resource = "${aws_s3_bucket.dr[0].arn}/*" }
    ]
  })
}

resource "aws_s3_bucket_replication_configuration" "primary_to_dr" {
  count      = local.enable_dr_runtime ? 1 : 0
  provider   = aws.primary
  depends_on = [aws_s3_bucket_versioning.primary, aws_s3_bucket_versioning.dr]
  role       = aws_iam_role.s3_replication[0].arn
  bucket     = aws_s3_bucket.primary.id

  rule {
    id     = "replicate-all"
    status = "Enabled"
    filter {}
    destination {
      bucket        = aws_s3_bucket.dr[0].arn
      storage_class = "STANDARD"
    }
    delete_marker_replication { status = "Disabled" }
  }
}
