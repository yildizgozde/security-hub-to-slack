data "aws_caller_identity" "current" {}

resource "aws_cloudwatch_event_rule" "SecurityHubFindingsToSlack" {
  name        = "SecurityHubFindingsToSlack"
  description = "CloudWatchEvents Rule to enable SecurityHub Findings in Slack "

  event_pattern = jsonencode({
    "source" = ["aws.securityhub"]
    "detail-type" : ["Security Hub Findings - Imported"]
  })
}

resource "aws_cloudwatch_event_rule" "GuardDutyFindingsToSlack" {
  name        = "GuardDutyFindingsToSlack"
  description = "CloudWatchEvents Rule to enable GuardDuty Findings in Slack "

  event_pattern = jsonencode({
    "source" : ["aws.guardduty"],
    "detail-type" : ["GuardDuty Finding"]
  })
}

resource "aws_lambda_permission" "SecurityHubFindingsToSlack" {
  statement_id  = "AllowExecutionFromCloudWatchForSH"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambdafindingsToSlack.arn
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.SecurityHubFindingsToSlack.arn
}

resource "aws_lambda_permission" "GuardDutyFindingsToSlack" {
  statement_id  = "AllowExecutionFromCloudWatchForGD"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambdafindingsToSlack.arn
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.GuardDutyFindingsToSlack.arn
}


resource "aws_cloudwatch_event_target" "SecurityHubFindingsToSlack" {
  rule      = aws_cloudwatch_event_rule.SecurityHubFindingsToSlack.name
  target_id = "SecurityHubFindingsToSlackLambda"
  arn       = aws_lambda_function.lambdafindingsToSlack.arn
}

resource "aws_cloudwatch_event_target" "GuardDutyFindingsToSlack" {
  rule      = aws_cloudwatch_event_rule.GuardDutyFindingsToSlack.name
  target_id = "GuardDutyFindingsToSlackLambda"
  arn       = aws_lambda_function.lambdafindingsToSlack.arn
}

resource "aws_iam_policy" "lambda_logging" {
  name        = "securityFindingsAlertPolicy"
  path        = "/"
  description = "IAM policy for logging from lambda"

  policy = data.aws_iam_policy_document.base.json
}

data "aws_iam_policy_document" "base" {
  statement {
    effect = "Allow"
    resources = [
      "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/securityFindingsAlert:log-stream:*",
      "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/securityFindingsAlert"
    ]

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
  }
}


resource "aws_iam_role_policy_attachment" "lambda" {
  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

resource "aws_iam_role" "lambda" {
  name               = "securityFindingsAlertLambda"
  path               = "/service-role/"
  assume_role_policy = data.aws_iam_policy_document.lambda.json
}

data "aws_iam_policy_document" "lambda" {
  statement {
    effect = "Allow"
    actions = [
      "sts:AssumeRole",
    ]
    principals {
      identifiers = [
        "lambda.amazonaws.com"
      ]
      type = "Service"
    }
  }
}

resource "aws_cloudwatch_log_group" "example" {
  name              = "/aws/lambda/securityFindingsAlert"
  retention_in_days = 14
}

resource "aws_lambda_function" "lambdafindingsToSlack" {
  function_name    = "securityFindingsAlert"
  handler          = "script.handler"
  role             = aws_iam_role.lambda.arn
  filename         = data.archive_file.lambda_zip_inline.output_path
  source_code_hash = data.archive_file.lambda_zip_inline.output_base64sha256
  runtime          = "python3.7"

  environment {
    variables = {
      slackChannel = var.SlackChannel
      webHookUrl   = var.IncomingWebHookURL
    }
  }
  memory_size = 128
  timeout     = 10
  description = "Lambda to push SecurityHub findings to Slack"

}

resource "null_resource" "package" {
  triggers = {
    "buildat" = timestamp()
  }

  provisioner "local-exec" {
    command = "rm -rf build && mkdir build && cp '${path.module}/script.py' build && pip3 install -t build requests"
  }
}

data "archive_file" "lambda_zip_inline" {
  type        = "zip"
  output_path = "/tmp/lambda_zip_inline.zip"
  source_dir  = "build"

  depends_on = [null_resource.package]
}
