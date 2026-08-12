locals {
  capital_one_lab_enabled = var.security_scenario_profile == "capital-one-lab"

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
    Statement = [
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
    ]
  })
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
