variable "account_name" {
  type = string
  default = ""
  description = "An extra identifier for the account that will show on all messages"
}

variable "slack_channel" {
  type = string
}

variable "slack_hook_url" {
  type        = string
  description = "Slack Hook URL (eg https://hooks.slack.com/services/xxxx/xxxx/xxxxxxxxxxxxx)"
}
variable "is_organization_trail" {
  type        = bool
  default     = false
  description = "Whether or not this is an organization trail. Can only be set to true if deploying this to a master account"
}
