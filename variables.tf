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
