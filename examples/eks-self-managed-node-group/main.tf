################################################################################
# RANDOM
################################################################################


resource "random_string" "sufix" {
  length  = 3
  special = false
}

data "aws_availability_zones" "available" {}

################################################################################
# Local Vars
################################################################################


locals {
  name   = "${var.name}-${random_string.sufix.result}"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)
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
}

################################################################################
# VPC Module
################################################################################


module "eks" {
  source  = "../.."

  cluster_name    = "${local.name}"
  cluster_version = "1.30"
  cluster_addons = {
    #coredns                = {}
    #eks-pod-identity-agent = {}
    #kube-proxy             = {}
    #vpc-cni                = {}
  }

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  self_managed_node_groups = {
    example = {
      ami_type      = "AL2_x86_64"
      instance_type = "m6i.large"
      min_size = 2
      max_size = 3
      desired_size = 2
    }
  }

  tags = merge(var.tags, {

  })
}