# Cloudtrail CIS Notifier

Creates a pipeline to send cloudtrail events to a slack account.

Events are filtered according to CIS recommended rules.

https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf

## Pipeline

`cloudtrail -> cloudwatch logs -> log stream -> lambda -> slack`

## Usage example
```hcl
module "cloudtrail-cis-notifier" {
  source = "github.com/broadwing/cloudtrail-cis-notifier"

  slack_channel  = "cloudtrail-notifier"
  slack_hook_url = "https://hooks.slack.com/services/xxxxx/xxxxxx/xxxxxx"
}

```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_slack_channel"></a> [slack\_channel](#input\_slack\_channel) | The slack channel to send notifications to | `string` |  | yes |
| <a name="input_slack_hook_url"></a> [slack\_hook\_url](#input\_slack\_hook\_url) | The slack api hook url used to send the notification. (eg https://hooks.slack.com/services/xxxx/xxxx/xxxxxxxxxxxxx) | `string` | | yes |
| <a name="input_account_name"></a> [account\_name](#input\_accoun\_name) | An optional account name that will be added to all messages if set. Useful if deployed to multiple accounts | `string` | `""` | no |
| <a name="input_is_organization_trail"></a> [is\_organization\_trail](#input\_is\_organization\_trail) | Whether or not this is an organization trail. Can only be set to true if deploying this to a master account | `bool` | `false` | no |
| <a name="input_resource_name"></a> [resource\_name](#input\_resource\_name) |The name of the resources to create. Such as the lambda function, cloudwatch log group, etc. | `string` | `cloudtrail-cis-notifier` | no |


## Testing

Run unit tests with `python ./lambda-source/test_cloudtrail_cis_notifier.py`

You can also simulate events and trigger messages by

  1. running `lambda-source/generate-test-message.sh | pbcopy` (you can also edit `decoded-test-messages.json` to make a subset of events to reduce noise)
  2. Open the lambda function in the in the aws console
  3. Click the `Test` tab and paste the generated message into the `Event Json` and click `Test`

## Alerts
| Name | Description|
| ---- | ----------|
| `3.1 Unauthorized API Call` | Event is an `UnauthorizedOperation` or `AccessDenied`
| `3.2 Console Login without MFA` | User successfully logged in without using MFA
| `3.3 Root Account Used` | Root account was used for any operation
| `3.4 IAM Policy Changed` | Any IAM policy was deleted, created, edited, attached, or detached
| `3.5 CloudTrail Configuration Changed` | A cloudtrail, including this one, was created, updated, deleted, stopped, or started
| `3.5 Slack Notifier Lambda Code Changed` | This lambda function code was changed
| `3.5 Slack Notifier Log Group or Subscription Filter Changed` | This module's log group or subscription were changed
| `3.6 Console Login Failure - Failed Authentication` | A failed login to this account or organization. Real user but wrong password.
| `3.6 Console Login Failure` | Unknown user id failed to login or another generic failed login attempt error
| `3.7 Scheduled Deletion of CMK` | A KMS key was disabled or scheduled for deletion
| `3.8 S3 Bucket Policy Changed` | A bucket's policy, ACL, Cors, lifecycle, or replication settings changed.
| `3.9 Config Service Changed` | An AWS Config Service was changed or disabled
| `3.10 Security Group Changed` | A security group rule was changed, created, or deleted
| `3.11 Network ACL Changed` | A network ACLE rule was changed, created, deleted, or the association changed
| `3.12 Network Gateway Changed` | A VPC internet gateway configuration changed
| `3.13 Network Route Table Changed` | A route table was created, updated, deleted, or the association changed
| `3.14 VPC Changed` | A VPC was created, deleted, or it's peering or other global attribute changed.
| `3.15 SNS Subscribers Changed` | An SNS topic was created, deleted, or the subscription changed.
