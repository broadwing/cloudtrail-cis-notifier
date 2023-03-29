resource "aws_cloudwatch_log_group" "cloudtrail_cis_notifier" {
  name = "/aws/cloudtrail/${var.resource_name}"

  tags = {
    ManagedBy = "terraform"
  }
}

resource "aws_iam_role" "cloudtrail_cis_notifier" {
  name               = "cloudtrail-cis-notifier"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "cloudtrail_cis_notifier" {
  name   = "cloudtrail-cis-notifier"
  role   = aws_iam_role.cloudtrail_cis_notifier.id
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
        "${aws_cloudwatch_log_group.cloudtrail_cis_notifier.arn}:*"
      ]

    }
  ]
}
EOF
}
