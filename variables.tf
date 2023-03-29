variable "slack_channel" {
  type = string
  description = "The slack channel to send notifications to"
}

variable "slack_hook_url" {
  type        = string
  description = "The slack api hook url used to send the notification. (eg https://hooks.slack.com/services/xxxx/xxxx/xxxxxxxxxxxxx)"
}

variable "account_name" {
  type        = string
  default     = ""
  description = "An optional account name that will be added to all messages if set. Useful if deployed to multiple accounts"
}

variable "is_organization_trail" {
  type        = bool
  default     = false
  description = "Whether or not this is an organization trail. Can only be set to true if deploying this to a master account"
}

variable "resource_name" {
  type        = string
  default     = "cloudtrail-cis-notifier"
  description = "The name of the resources to create. Such as the lambda function, cloudwatch log group, etc."
}
