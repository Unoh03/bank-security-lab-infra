locals {
  wazuh_push_primary_queue_name        = "${local.name}-wazuh-push-primary"
  wazuh_push_primary_dlq_name          = "${local.name}-wazuh-push-primary-dlq"
  wazuh_push_primary_lambda_name       = "${local.name}-wazuh-push-primary"
  wazuh_push_primary_lambda_log_group  = "/aws/lambda/${local.wazuh_push_primary_lambda_name}"
  wazuh_push_dvwa_subscription_name    = "${local.name}-wazuh-push-dvwa"
  wazuh_push_queue_retention_seconds   = 345600
  wazuh_push_dlq_retention_seconds     = 1209600
  wazuh_push_queue_visibility_seconds  = 90
  wazuh_push_queue_max_receive_count   = 5
  wazuh_push_lambda_log_retention_days = 7
}

check "wazuh_push_requires_reader" {
  assert {
    condition     = !var.enable_wazuh_push_transport || var.enable_wazuh_log_reader
    error_message = "enable_wazuh_push_transport requires enable_wazuh_log_reader so the local shadow consumer has an explicit read-only role."
  }
}

data "archive_file" "wazuh_push_primary" {
  count = var.enable_wazuh_push_transport ? 1 : 0

  type        = "zip"
  source_file = "${path.module}/lambda/wazuh_push_forwarder.py"
  output_path = "${path.module}/.terraform/wazuh_push_forwarder.zip"
}

resource "aws_sqs_queue" "wazuh_push_primary_dlq" {
  count = var.enable_wazuh_push_transport ? 1 : 0

  name                      = local.wazuh_push_primary_dlq_name
  message_retention_seconds = local.wazuh_push_dlq_retention_seconds
  sqs_managed_sse_enabled   = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_sqs_queue" "wazuh_push_primary" {
  count = var.enable_wazuh_push_transport ? 1 : 0

  name                       = local.wazuh_push_primary_queue_name
  message_retention_seconds  = local.wazuh_push_queue_retention_seconds
  receive_wait_time_seconds  = 20
  visibility_timeout_seconds = local.wazuh_push_queue_visibility_seconds
  sqs_managed_sse_enabled    = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.wazuh_push_primary_dlq[0].arn
    maxReceiveCount     = local.wazuh_push_queue_max_receive_count
  })

  lifecycle {
    prevent_destroy = true
  }
}

data "aws_iam_policy_document" "wazuh_push_primary_queue" {
  count = var.enable_wazuh_push_transport ? 1 : 0

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["sqs:*"]
    resources = [
      aws_sqs_queue.wazuh_push_primary[0].arn,
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sqs_queue_policy" "wazuh_push_primary" {
  count = var.enable_wazuh_push_transport ? 1 : 0

  queue_url = aws_sqs_queue.wazuh_push_primary[0].id
  policy    = data.aws_iam_policy_document.wazuh_push_primary_queue[0].json
}

data "aws_iam_policy_document" "wazuh_push_primary_lambda_assume" {
  count = var.enable_wazuh_push_transport ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "wazuh_push_primary_lambda" {
  count = var.enable_wazuh_push_transport ? 1 : 0

  name               = "${local.wazuh_push_primary_lambda_name}-lambda"
  description        = "Forwards every event from the approved Primary DVWA log group to the Wazuh shadow queue."
  assume_role_policy = data.aws_iam_policy_document.wazuh_push_primary_lambda_assume[0].json
}

resource "aws_cloudwatch_log_group" "wazuh_push_primary_lambda" {
  count = var.enable_wazuh_push_transport ? 1 : 0

  name              = local.wazuh_push_primary_lambda_log_group
  retention_in_days = local.wazuh_push_lambda_log_retention_days

  lifecycle {
    prevent_destroy = true
  }
}

data "aws_iam_policy_document" "wazuh_push_primary_lambda" {
  count = var.enable_wazuh_push_transport ? 1 : 0

  statement {
    sid    = "WriteForwarderLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.wazuh_push_primary_lambda[0].arn}:*"]
  }

  statement {
    sid       = "SendApprovedEventsToPrimaryQueue"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.wazuh_push_primary[0].arn]
  }
}

resource "aws_iam_role_policy" "wazuh_push_primary_lambda" {
  count = var.enable_wazuh_push_transport ? 1 : 0

  name   = "send-approved-dvwa-events"
  role   = aws_iam_role.wazuh_push_primary_lambda[0].id
  policy = data.aws_iam_policy_document.wazuh_push_primary_lambda[0].json
}

resource "aws_lambda_function" "wazuh_push_primary" {
  count = var.enable_wazuh_push_transport ? 1 : 0

  function_name = local.wazuh_push_primary_lambda_name
  description   = "Normalizes every approved DVWA CloudWatch Logs event and enqueues it for the local Wazuh shadow bridge."
  role          = aws_iam_role.wazuh_push_primary_lambda[0].arn
  runtime       = "python3.12"
  handler       = "wazuh_push_forwarder.lambda_handler"
  architectures = ["x86_64"]
  filename      = data.archive_file.wazuh_push_primary[0].output_path

  source_code_hash = data.archive_file.wazuh_push_primary[0].output_base64sha256
  memory_size      = 128
  timeout          = 30

  environment {
    variables = {
      EXPECTED_ACCOUNT_ID = data.aws_caller_identity.current.account_id
      EXPECTED_LOG_GROUP  = aws_cloudwatch_log_group.dvwa_primary.name
      QUEUE_URL           = aws_sqs_queue.wazuh_push_primary[0].id
      SCHEMA_VERSION      = "1"
      SOURCE_NAME         = "dvwa"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.wazuh_push_primary_lambda,
    aws_iam_role_policy.wazuh_push_primary_lambda,
  ]
}

resource "aws_lambda_permission" "wazuh_push_dvwa" {
  count = var.enable_wazuh_push_transport ? 1 : 0

  statement_id   = "AllowDvwaCloudWatchLogs"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.wazuh_push_primary[0].function_name
  principal      = "logs.amazonaws.com"
  source_account = data.aws_caller_identity.current.account_id
  source_arn     = "${aws_cloudwatch_log_group.dvwa_primary.arn}:*"
}

resource "aws_cloudwatch_log_subscription_filter" "wazuh_push_dvwa" {
  count = var.enable_wazuh_push_transport ? 1 : 0

  name            = local.wazuh_push_dvwa_subscription_name
  log_group_name  = aws_cloudwatch_log_group.dvwa_primary.name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.wazuh_push_primary[0].arn

  depends_on = [aws_lambda_permission.wazuh_push_dvwa]
}
