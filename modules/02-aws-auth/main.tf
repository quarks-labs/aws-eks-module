
################################################################################
# aws-auth configmap
################################################################################

locals {
  aws_auth_configmap_data = {
    mapRoles    = yamlencode(var.aws_auth_roles)
    mapUsers    = yamlencode(var.aws_auth_users)
    mapAccounts = yamlencode(var.aws_auth_accounts)
  }
}

resource "kubernetes_config_map" "aws_auth" {
  count = var.create && var.create_aws_auth_configmap ? 1 : 0

  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
  }

  data = local.aws_auth_configmap_data

  lifecycle {
    ignore_changes = [data, metadata[0].labels, metadata[0].annotations]
  }
}

resource "kubernetes_config_map_v1_data" "aws_auth" {
  count = var.create && var.manage_aws_auth_configmap ? 1 : 0
  force = true
  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
  }
  data = local.aws_auth_configmap_data
  depends_on = [
    kubernetes_config_map.aws_auth,
  ]
}
