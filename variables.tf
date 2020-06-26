variable "env" {
  type = string
}

variable "slack_channel" {
  type = string
}

variable "slack_hook_url" {
  type        = string
  description = "Slack Hook URL (eg https://hooks.slack.com/services/xxxx/xxxx/xxxxxxxxxxxxx)"
}
