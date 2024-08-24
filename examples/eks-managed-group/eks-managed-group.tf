################################################################################
# EKS Module
################################################################################


module "eks" {
  source  = "../.."

  cluster_name    = "${local.name}"
  cluster_version = "1.30"
  subnet_ids = module.vpc.private_subnets
  vpc_id     = module.vpc.vpc_id
  
  cluster_addons = {
    coredns                = {}
    eks-pod-identity-agent = {}
    kube-proxy             = {}
    vpc-cni                = {}
  }


  eks_managed_node_groups = {
    example = {
      ami_type       = "BOTTLEROCKET_x86_64"
      instance_types = ["t3a.xlarge"]

      min_size = 1
      max_size = 2
      desired_size = 1

      bootstrap_extra_args = <<-EOT
        # The admin host container provides SSH access and runs with "superpowers".
        # It is disabled by default, but can be disabled explicitly.
        [settings.host-containers.admin]
        enabled = false

        # The control host container provides out-of-band access via SSM.
        # It is enabled by default, and can be disabled if you do not expect to use SSM.
        # This could leave you with no way to access the API and change settings on an existing node!
        [settings.host-containers.control]
        enabled = true

        # extra args added
        [settings.kernel]
        lockdown = "integrity"
      EOT
    }
  }

  tags = merge(
    var.tags, {
        
    }
  )

  depends_on = [ module.vpc ]
}
