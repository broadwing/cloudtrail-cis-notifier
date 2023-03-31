data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda-source"
  output_path = "${path.module}/cloudtrail-cis-notifier.zip"
}

resource "aws_lambda_function" "cloudtrail_cis_notifier" {
  filename         = "${path.module}/cloudtrail-cis-notifier.zip"
  function_name    = var.resource_name
  role             = aws_iam_role.cloudtrail_cis_notifier_lambda.arn
  handler          = "cloudtrail_cis_notifier.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.9"

  environment {
    variables = {
      account_name     = var.account_name
      slack_channel    = var.slack_channel
      hook_url         = var.slack_hook_url
      SEARCH_PREFIX    = "https://console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#logEventViewer:group=${aws_cloudwatch_log_group.cloudtrail_cis_notifier.name}"
      resource_name    = var.resource_name
      skip_event_names = jsonencode(var.skip_event_names)
      skip_rule_ids    = jsonencode(var.skip_rule_ids)
    }
  }
}

resource "aws_cloudwatch_log_group" "cloudtrail_cis_notifier_lambda" {
  name = "/aws/lambda/${var.resource_name}"

  tags = {
    ManagedBy = "terraform"
  }
}

resource "aws_iam_role" "cloudtrail_cis_notifier_lambda" {
  name = "cloudtrail-cis-notifier-lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "cloudtrail_cis_notifier_lambda_policy" {
  name = "cloudtrail-cis-notifier-lambda"
  role = aws_iam_role.cloudtrail_cis_notifier_lambda.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {

      "Sid": "AWSCloudTrailCreateLogStream2014110",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": [
        "${aws_cloudwatch_log_group.cloudtrail_cis_notifier_lambda.arn}:*"
      ]
    },
    {
        "Effect": "Allow",
        "Action": [
            "kms:Decrypt"
        ],
        "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_lambda_alias" "cloudtrail_cis_notifier" {
  name             = "cloudtrail-cis-notifier"
  description      = "Cloudtrail CIS Notifier"
  function_name    = aws_lambda_function.cloudtrail_cis_notifier.function_name
  function_version = "$LATEST"
}

# Allow cloudwatch to trigger lambda
resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cloudtrail_cis_notifier.function_name
  principal     = "logs.${data.aws_region.current.name}.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.cloudtrail_cis_notifier.arn}:*"
}

resource "aws_cloudwatch_log_subscription_filter" "cloudtrail-cis-notifier" {
  name            = "cloudtrail-cis-notifier"
  log_group_name  = aws_cloudwatch_log_group.cloudtrail_cis_notifier.name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.cloudtrail_cis_notifier.arn
}
