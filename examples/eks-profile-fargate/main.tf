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

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }
}

################################################################################
# EKS Module
################################################################################


resource "aws_iam_policy" "additional" {
  name = "${local.name}-additional"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}


module "eks" {
  source = "../.."

  cluster_name                   =  var.region
  cluster_version                = "1.30"
  cluster_endpoint_public_access = true
  
  cluster_addons_timeouts = { 
    create = "30m"
  }

  cluster_addons = {

    coredns = {
      resolve_conflicts_on_update = "PRESERVE"
      configuration_values = jsonencode({
        computeType = "fargate"
      })
    }
    kube-proxy = {}
    vpc-cni    = {}
  }

  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.intra_subnets
  create_cluster_security_group = false
  create_node_security_group    = false

  fargate_profile_defaults = {
    iam_role_additional_policies = {
      additional = aws_iam_policy.additional.arn
    }
  }

  fargate_profiles = {
    fargate_profile = {
      name = "fargate_profile"
      selectors = [
        {
          namespace = "backend"
          labels = {
            Application = "backend"
          }
        },
        {
          namespace = "app"
          labels = {
            Application = "app"
          }
        }
      ]

      subnet_ids = [module.vpc.private_subnets[1]]

      tags = {
        Owner = "secondary"
      }
    }
    kube-system = {
      selectors = [
        { namespace = "kube-system" }
      ]
    }
  }

  tags = merge(var.tags, { })
}


