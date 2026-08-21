locals {
  capital_one_lab_enabled = var.security_scenario_profile == "capital-one-lab"
  capital_one_negative_control_trusted_principal_arn = try(
    trimspace(data.terraform_remote_state.foundation.outputs.wazuh_reader_trusted_principal_arn),
    ""
  )
  capital_one_negative_control_assume_principal_arn = local.capital_one_negative_control_trusted_principal_arn != "" ? (
    local.capital_one_negative_control_trusted_principal_arn
  ) : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/capital-one-negative-control-principal-not-configured"

  hardened_karpenter_metadata_options = {
    httpEndpoint            = "enabled"
    httpProtocolIPv6        = "disabled"
    httpPutResponseHopLimit = 1
    httpTokens              = "required"
  }

  primary_karpenter_metadata_options = merge(
    local.hardened_karpenter_metadata_options,
    {
      httpPutResponseHopLimit = local.capital_one_lab_enabled ? 2 : 1
      httpTokens              = local.capital_one_lab_enabled ? "optional" : "required"
    }
  )
}

resource "aws_iam_role_policy" "primary_karpenter_capital_one_lab" {
  count    = local.capital_one_lab_enabled ? 1 : 0
  provider = aws.primary
  name     = "capital-one-validation-read"
  role     = module.primary_karpenter.node_iam_role_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid      = "ListValidationPrefix"
          Effect   = "Allow"
          Action   = ["s3:ListBucket"]
          Resource = aws_s3_bucket.primary.arn
          Condition = {
            StringLike = {
              "s3:prefix" = ["validation", "validation/*"]
            }
          }
        },
        {
          Sid      = "ReadValidationObjects"
          Effect   = "Allow"
          Action   = ["s3:GetObject"]
          Resource = "${aws_s3_bucket.primary.arn}/validation/*"
        }
      ],
      local.capital_one_secondary_control_enabled ? [
        {
          Sid      = "ReadSecondaryControlObject"
          Effect   = "Allow"
          Action   = ["s3:GetObject"]
          Resource = "${aws_s3_bucket.capital_one_secondary_control[0].arn}/${local.capital_one_secondary_control_object_key}"
        },
        {
          Sid      = "ReadOtherPrefixControlObject"
          Effect   = "Allow"
          Action   = ["s3:GetObject"]
          Resource = "${aws_s3_bucket.primary.arn}/${local.capital_one_other_prefix_control_object_key}"
        }
      ] : []
    )
  })
}

data "aws_iam_policy_document" "capital_one_negative_control_assume" {
  count    = local.capital_one_secondary_control_enabled ? 1 : 0
  provider = aws.primary

  statement {
    sid     = "AllowExplicitSameAccountPrincipal"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [local.capital_one_negative_control_assume_principal_arn]
    }
  }
}

resource "aws_iam_role" "capital_one_negative_control" {
  count    = local.capital_one_secondary_control_enabled ? 1 : 0
  provider = aws.primary

  name                 = "${local.name}-capital-one-negative-control"
  description          = "Minimal lab role for the independent other-principal CloudTrail negative control."
  assume_role_policy   = data.aws_iam_policy_document.capital_one_negative_control_assume[0].json
  max_session_duration = 3600

  lifecycle {
    precondition {
      condition = try(
        local.capital_one_negative_control_trusted_principal_arn != "" &&
        split(":", local.capital_one_negative_control_trusted_principal_arn)[4] == data.aws_caller_identity.current.account_id &&
        can(regex(
          "^arn:[^:]+:iam::${data.aws_caller_identity.current.account_id}:(user|role)/.+$",
          local.capital_one_negative_control_trusted_principal_arn
        )),
        false
      )
      error_message = "minimal + capital-one-lab requires the Foundation wazuh_reader_trusted_principal_arn to be a same-account IAM user or role ARN."
    }
  }
}

data "aws_iam_policy_document" "capital_one_negative_control" {
  count    = local.capital_one_secondary_control_enabled ? 1 : 0
  provider = aws.primary

  statement {
    sid       = "ReadExactPrimaryValidationObject"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.primary.arn}/${local.capital_one_secondary_control_object_key}"]
  }
}

resource "aws_iam_role_policy" "capital_one_negative_control" {
  count    = local.capital_one_secondary_control_enabled ? 1 : 0
  provider = aws.primary

  name   = "capital-one-negative-control-read"
  role   = aws_iam_role.capital_one_negative_control[0].id
  policy = data.aws_iam_policy_document.capital_one_negative_control[0].json
}

check "security_scenario_metadata_boundary" {
  assert {
    condition = (
      local.hardened_karpenter_metadata_options.httpTokens == "required" &&
      local.hardened_karpenter_metadata_options.httpPutResponseHopLimit == 1 &&
      local.primary_karpenter_metadata_options.httpTokens == (local.capital_one_lab_enabled ? "optional" : "required") &&
      local.primary_karpenter_metadata_options.httpPutResponseHopLimit == (local.capital_one_lab_enabled ? 2 : 1)
    )
    error_message = "The security scenario must keep DR hardened and may weaken only the Primary Karpenter metadata settings in capital-one-lab."
  }
}
