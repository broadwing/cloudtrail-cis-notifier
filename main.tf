data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

resource "random_pet" "name" {
  length = 1
}
