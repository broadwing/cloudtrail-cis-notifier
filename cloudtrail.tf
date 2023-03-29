locals {
  random_bucket_name = "cloudtrail-cis-notifier-${random_pet.name.id}"
  bucket_name = var.account_name == "" ? local.random_bucket_name : "${var.account_name}-${local.random_bucket_name}"
}

resource "aws_cloudtrail" "cloudtrail_cis_notifier" {
  name                          = "cloudtrail_cis_notifier"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_cis_notifier.id
  cloud_watch_logs_group_arn     = "${aws_cloudwatch_log_group.cloudtrail_cis_notifier.arn}:*" # CloudTrail requires the Log Stream wildcard
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cis_notifier.arn
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  # Not sure why terraform always thinks this needs to be applied. It does persist on a run
  event_selector {
    read_write_type           = "WriteOnly"
    include_management_events = true
  }

  # Ignore changes because of ^
  lifecycle {
    ignore_changes = [event_selector]
  }

  tags = {
    ManagedBy = "terraform"
  }
}

resource "aws_s3_bucket" "cloudtrail_cis_notifier" {
  bucket        = local.bucket_name
  force_destroy = true

  tags = {
    ManagedBy = "terraform"
  }
}

# Bucket policy to allow CloudTrail to write to the bucket
resource "aws_s3_bucket_policy" "cloudtrail_cis_notifier" {
  bucket = aws_s3_bucket.cloudtrail_cis_notifier.id

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${local.bucket_name}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${local.bucket_name}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}
