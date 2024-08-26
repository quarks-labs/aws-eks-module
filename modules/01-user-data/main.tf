resource "null_resource" "validate_cluster_service_cidr" {
  lifecycle {
    precondition {
      condition     = var.create ? length(local.cluster_service_cidr) > 6 : true
      error_message = "`cluster_service_cidr` is required when `create = true`."
    }
  }
}

locals {
  ami_type_to_user_data_type = {
    AL2_x86_64                 = "linux"
    AL2_x86_64_GPU             = "linux"
    AL2_ARM_64                 = "linux"
    BOTTLEROCKET_ARM_64        = "bottlerocket"
    BOTTLEROCKET_x86_64        = "bottlerocket"
    BOTTLEROCKET_ARM_64_NVIDIA = "bottlerocket"
    BOTTLEROCKET_x86_64_NVIDIA = "bottlerocket"
    WINDOWS_CORE_2019_x86_64   = "windows"
    WINDOWS_FULL_2019_x86_64   = "windows"
    WINDOWS_CORE_2022_x86_64   = "windows"
    WINDOWS_FULL_2022_x86_64   = "windows"
    AL2023_x86_64_STANDARD     = "al2023"
    AL2023_ARM_64_STANDARD     = "al2023"
  }
  user_data_type = try(local.ami_type_to_user_data_type[var.ami_type], var.platform)

  template_path = {
    al2023       = "${path.module}/../../tpl/al2023_user_data.tpl"
    bottlerocket = "${path.module}/../../tpl/bottlerocket_user_data.tpl"
    linux        = "${path.module}/../../tpl/linux_user_data.tpl"
    windows      = "${path.module}/../../tpl/windows_user_data.tpl"
  }

  cluster_service_cidr = try(coalesce(var.cluster_service_ipv4_cidr, var.cluster_service_cidr), "")
  cluster_dns_ips      = flatten(concat([try(cidrhost(local.cluster_service_cidr, 10), "")], var.additional_cluster_dns_ips))

  user_data = base64encode(templatefile(
    coalesce(var.user_data_template_path, local.template_path[local.user_data_type]),
    {
      enable_bootstrap_user_data = var.enable_bootstrap_user_data
      cluster_name        = var.cluster_name
      cluster_endpoint    = var.cluster_endpoint
      cluster_auth_base64 = var.cluster_auth_base64
      cluster_service_cidr = local.cluster_service_cidr
      cluster_ip_family    = var.cluster_ip_family
      cluster_dns_ips = "[${join(", ", formatlist("\"%s\"", local.cluster_dns_ips))}]"
      bootstrap_extra_args     = var.bootstrap_extra_args
      pre_bootstrap_user_data  = var.pre_bootstrap_user_data
      post_bootstrap_user_data = var.post_bootstrap_user_data
    }
  ))

  user_data_type_to_rendered = {
    al2023 = {
      user_data = var.create ? try(data.cloudinit_config.al2023_eks_managed_node_group[0].rendered, local.user_data) : ""
    }
    bottlerocket = {
      user_data = var.create && local.user_data_type == "bottlerocket" && (var.enable_bootstrap_user_data || var.user_data_template_path != "" || var.bootstrap_extra_args != "") ? local.user_data : ""
    }
    linux = {
      user_data = var.create ? try(data.cloudinit_config.linux_eks_managed_node_group[0].rendered, local.user_data) : ""
    }
    windows = {
      user_data = var.create && local.user_data_type == "windows" && (var.enable_bootstrap_user_data || var.user_data_template_path != "" || var.pre_bootstrap_user_data != "") ? local.user_data : ""
    }
  }
}

data "cloudinit_config" "linux_eks_managed_node_group" {
  count = var.create && local.user_data_type == "linux" && var.is_eks_managed_node_group && !var.enable_bootstrap_user_data && var.pre_bootstrap_user_data != "" && var.user_data_template_path == "" ? 1 : 0

  base64_encode = true
  gzip          = false
  boundary      = "//"
  part {
    content      = var.pre_bootstrap_user_data
    content_type = "text/x-shellscript"
  }
}

locals {
  nodeadm_cloudinit = var.enable_bootstrap_user_data ? concat(
    var.cloudinit_pre_nodeadm,
    [{
      content_type = "application/node.eks.aws"
      content      = base64decode(local.user_data)
    }],
    var.cloudinit_post_nodeadm
  ) : var.cloudinit_pre_nodeadm
}

data "cloudinit_config" "al2023_eks_managed_node_group" {
  count = var.create && local.user_data_type == "al2023" && length(local.nodeadm_cloudinit) > 0 ? 1 : 0

  base64_encode = true
  gzip          = false
  boundary      = "MIMEBOUNDARY"

  dynamic "part" {
    for_each = { for i, v in local.nodeadm_cloudinit : i => v }

    content {
      content      = part.value.content
      content_type = try(part.value.content_type, null)
      filename     = try(part.value.filename, null)
      merge_type   = try(part.value.merge_type, null)
    }
  }
}
