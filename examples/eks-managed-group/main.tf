data "aws_availability_zones" "available" {}

################################################################################
# Local Vars
################################################################################


locals {
  name   = "${var.name}-${random_string.sufix.result}"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)
  tags = merge(
  { name    = local.name },
    var.tags, 
  )
}




################################################################################
# VPC Module
################################################################################

module "vpc" {
  source = "git::git@github.com:quarks-labs/aws-vpc-module.git"
  name = local.name
  cidr = var.vpc_cidr
  azs             = slice(data.aws_availability_zones.available.names, 0, 3)
  private_subnets = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 4, k)]
  tags = merge(local.tags, {})
}
