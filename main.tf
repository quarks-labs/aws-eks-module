data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_iam_session_context" "current" {
  arn = data.aws_caller_identity.current.arn
}

locals {
  create = var.create && var.putin_khuylo
  partition = data.aws_partition.current.partition
  cluster_role = try(aws_iam_role.this[0].arn, var.iam_role_arn)
  create_outposts_local_cluster    = length(var.outpost_config) > 0
  enable_cluster_encryption_config = length(var.cluster_encryption_config) > 0 && !local.create_outposts_local_cluster
}

################################################################################
# Cluster
################################################################################

resource "aws_eks_cluster" "this" {
  count = local.create ? 1 : 0
  name                          = var.cluster_name
  role_arn                      = local.cluster_role
  version                       = var.cluster_version
  enabled_cluster_log_types     = var.cluster_enabled_log_types
  bootstrap_self_managed_addons = var.bootstrap_self_managed_addons
  access_config {
    authentication_mode = var.authentication_mode
    bootstrap_cluster_creator_admin_permissions = false
  }
  vpc_config {
    security_group_ids      = compact(distinct(concat(var.cluster_additional_security_group_ids, [local.cluster_security_group_id])))
    subnet_ids              = coalescelist(var.control_plane_subnet_ids, var.subnet_ids)
    endpoint_private_access = var.cluster_endpoint_private_access
    endpoint_public_access  = var.cluster_endpoint_public_access
    public_access_cidrs     = var.cluster_endpoint_public_access_cidrs
  }
  dynamic "kubernetes_network_config" {
    for_each = local.create_outposts_local_cluster ? [] : [1]
    content {
      ip_family         = var.cluster_ip_family
      service_ipv4_cidr = var.cluster_service_ipv4_cidr
      service_ipv6_cidr = var.cluster_service_ipv6_cidr
    }
  }
  dynamic "outpost_config" {
    for_each = local.create_outposts_local_cluster ? [var.outpost_config] : []
    content {
      control_plane_instance_type = outpost_config.value.control_plane_instance_type
      outpost_arns                = outpost_config.value.outpost_arns
    }
  }
  dynamic "encryption_config" {
    for_each = local.enable_cluster_encryption_config ? [var.cluster_encryption_config] : []
    content {
      provider {
        key_arn = var.create_kms_key ? module.kms.key_arn : encryption_config.value.provider_key_arn
      }
      resources = encryption_config.value.resources
    }
  }

  dynamic "upgrade_policy" {
    for_each = length(var.cluster_upgrade_policy) > 0 ? [var.cluster_upgrade_policy] : []
    content {
      support_type = try(upgrade_policy.value.support_type, null)
    }
  }
  tags = merge(
    { terraform-aws-modules = "eks" },
    var.tags,
    var.cluster_tags,
  )
  timeouts {
    create = try(var.cluster_timeouts.create, null)
    update = try(var.cluster_timeouts.update, null)
    delete = try(var.cluster_timeouts.delete, null)
  }

  depends_on = [
    aws_iam_role_policy_attachment.this,
    aws_security_group_rule.cluster,
    aws_security_group_rule.node,
    aws_cloudwatch_log_group.this,
    aws_iam_policy.cni_ipv6_policy,
  ]

  lifecycle {
    ignore_changes = [
      access_config[0].bootstrap_cluster_creator_admin_permissions
    ]
  }
}

resource "aws_ec2_tag" "cluster_primary_security_group" {
  for_each = { for k, v in merge(var.tags, var.cluster_tags) :
    k => v if local.create && k != "Name" && var.create_cluster_primary_security_group_tags
  }
  resource_id = aws_eks_cluster.this[0].vpc_config[0].cluster_security_group_id
  key         = each.key
  value       = each.value
}

resource "aws_cloudwatch_log_group" "this" {
  count = local.create && var.create_cloudwatch_log_group ? 1 : 0
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = var.cloudwatch_log_group_retention_in_days
  kms_key_id        = var.cloudwatch_log_group_kms_key_id
  log_group_class   = var.cloudwatch_log_group_class
  tags = merge(
    var.tags,
    var.cloudwatch_log_group_tags,
    { Name = "/aws/eks/${var.cluster_name}/cluster" }
  )
}

################################################################################
# Access Entry
################################################################################

locals {
  bootstrap_cluster_creator_admin_permissions = {
    cluster_creator = {
      principal_arn = data.aws_iam_session_context.current.issuer_arn
      type          = "STANDARD"

      policy_associations = {
        admin = {
          policy_arn = "arn:${local.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = {
            type = "cluster"
          }
        }
      }
    }
  }
  merged_access_entries = merge(
    { for k, v in local.bootstrap_cluster_creator_admin_permissions : k => v if var.enable_cluster_creator_admin_permissions },
    var.access_entries,
  )
  flattened_access_entries = flatten([
    for entry_key, entry_val in local.merged_access_entries : [
      for pol_key, pol_val in lookup(entry_val, "policy_associations", {}) :
      merge(
        {
          principal_arn = entry_val.principal_arn
          entry_key     = entry_key
          pol_key       = pol_key
        },
        { for k, v in {
          association_policy_arn              = pol_val.policy_arn
          association_access_scope_type       = pol_val.access_scope.type
          association_access_scope_namespaces = lookup(pol_val.access_scope, "namespaces", [])
        } : k => v if !contains(["EC2_LINUX", "EC2_WINDOWS", "FARGATE_LINUX"], lookup(entry_val, "type", "STANDARD")) },
      )
    ]
  ])
}

resource "aws_eks_access_entry" "this" {
  for_each = { for k, v in local.merged_access_entries : k => v if local.create }
  cluster_name      = aws_eks_cluster.this[0].name
  kubernetes_groups = try(each.value.kubernetes_groups, null)
  principal_arn     = each.value.principal_arn
  type              = try(each.value.type, "STANDARD")
  user_name         = try(each.value.user_name, null)
  tags = merge(var.tags, try(each.value.tags, {}))
}

resource "aws_eks_access_policy_association" "this" {
  for_each = { for k, v in local.flattened_access_entries : "${v.entry_key}_${v.pol_key}" => v if local.create }
  access_scope {
    namespaces = try(each.value.association_access_scope_namespaces, [])
    type       = each.value.association_access_scope_type
  }
  cluster_name = aws_eks_cluster.this[0].name
  policy_arn    = each.value.association_policy_arn
  principal_arn = each.value.principal_arn
  depends_on = [
    aws_eks_access_entry.this,
  ]
}

################################################################################
# KMS Key
################################################################################

module "kms" {
  source  = "git::git@github.com:quarks-labs/aws-kms-module.git"

  create = local.create && var.create_kms_key && local.enable_cluster_encryption_config # not valid on Outposts

  description             = coalesce(var.kms_key_description, "${var.cluster_name} cluster encryption key")
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = var.kms_key_deletion_window_in_days
  enable_key_rotation     = var.enable_kms_key_rotation

  enable_default_policy     = var.kms_key_enable_default_policy
  key_owners                = var.kms_key_owners
  key_administrators        = coalescelist(var.kms_key_administrators, [data.aws_iam_session_context.current.issuer_arn])
  key_users                 = concat([local.cluster_role], var.kms_key_users)
  key_service_users         = var.kms_key_service_users
  source_policy_documents   = var.kms_key_source_policy_documents
  override_policy_documents = var.kms_key_override_policy_documents

  aliases = var.kms_key_aliases
  computed_aliases = {
    cluster = { name = "eks/${var.cluster_name}" }
  }

  tags = merge(
    { terraform-aws-modules = "eks" },
    var.tags,
  )
}

################################################################################
# Cluster Security Group
################################################################################

locals {
  cluster_sg_name   = coalesce(var.cluster_security_group_name, "${var.cluster_name}-cluster")
  create_cluster_sg = local.create && var.create_cluster_security_group

  cluster_security_group_id = local.create_cluster_sg ? aws_security_group.cluster[0].id : var.cluster_security_group_id

  # Do not add rules to node security group if the module is not creating it
  cluster_security_group_rules = { for k, v in {
    ingress_nodes_443 = {
      description                = "Node groups to cluster API"
      protocol                   = "tcp"
      from_port                  = 443
      to_port                    = 443
      type                       = "ingress"
      source_node_security_group = true
    }
  } : k => v if local.create_node_sg }
}

resource "aws_security_group" "cluster" {
  count = local.create_cluster_sg ? 1 : 0

  name        = var.cluster_security_group_use_name_prefix ? null : local.cluster_sg_name
  name_prefix = var.cluster_security_group_use_name_prefix ? "${local.cluster_sg_name}${var.prefix_separator}" : null
  description = var.cluster_security_group_description
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    { "Name" = local.cluster_sg_name },
    var.cluster_security_group_tags
  )

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "cluster" {
  for_each = { for k, v in merge(local.cluster_security_group_rules, var.cluster_security_group_additional_rules ) : k => v if local.create_cluster_sg }
  security_group_id = aws_security_group.cluster[0].id
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  type              = each.value.type
  description              = lookup(each.value, "description", null)
  cidr_blocks              = lookup(each.value, "cidr_blocks", null)
  ipv6_cidr_blocks         = lookup(each.value, "ipv6_cidr_blocks", null)
  prefix_list_ids          = lookup(each.value, "prefix_list_ids", null)
  self                     = lookup(each.value, "self", null)
  source_security_group_id = try(each.value.source_node_security_group, false) ? local.node_security_group_id : lookup(each.value, "source_security_group_id", null)
}

################################################################################
# IRSA
################################################################################

locals {
  # Not available on outposts
  create_oidc_provider = local.create && var.enable_irsa && !local.create_outposts_local_cluster
  oidc_root_ca_thumbprint = local.create_oidc_provider && var.include_oidc_root_ca_thumbprint ? [data.tls_certificate.this[0].certificates[0].sha1_fingerprint] : []
}

data "tls_certificate" "this" {
  count = local.create_oidc_provider && var.include_oidc_root_ca_thumbprint ? 1 : 0
  url = aws_eks_cluster.this[0].identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "oidc_provider" {
  count = local.create_oidc_provider ? 1 : 0

  client_id_list  = distinct(compact(concat(["sts.amazonaws.com"], var.openid_connect_audiences)))
  thumbprint_list = concat(local.oidc_root_ca_thumbprint, var.custom_oidc_thumbprints)
  url             = aws_eks_cluster.this[0].identity[0].oidc[0].issuer

  tags = merge(
    { Name = "${var.cluster_name}-eks-irsa" },
    var.tags
  )
}

################################################################################
# IAM Role
################################################################################

locals {
  create_iam_role        = local.create && var.create_iam_role
  iam_role_name          = coalesce(var.iam_role_name, "${var.cluster_name}-cluster")
  iam_role_policy_prefix = "arn:${local.partition}:iam::aws:policy"
  cluster_encryption_policy_name = coalesce(var.cluster_encryption_policy_name, "${local.iam_role_name}-ClusterEncryption")
}

data "aws_iam_policy_document" "assume_role_policy" {
  count = local.create && var.create_iam_role ? 1 : 0

  statement {
    sid     = "EKSClusterAssumeRole"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }

    dynamic "principals" {
      for_each = local.create_outposts_local_cluster ? [1] : []

      content {
        type = "Service"
        identifiers = [
          "ec2.amazonaws.com",
        ]
      }
    }
  }
}

resource "aws_iam_role" "this" {
  count = local.create_iam_role ? 1 : 0

  name        = var.iam_role_use_name_prefix ? null : local.iam_role_name
  name_prefix = var.iam_role_use_name_prefix ? "${local.iam_role_name}${var.prefix_separator}" : null
  path        = var.iam_role_path
  description = var.iam_role_description

  assume_role_policy    = data.aws_iam_policy_document.assume_role_policy[0].json
  permissions_boundary  = var.iam_role_permissions_boundary
  force_detach_policies = true

  dynamic "inline_policy" {
    for_each = var.create_cloudwatch_log_group ? [1] : []
    content {
      name = local.iam_role_name

      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Action   = ["logs:CreateLogGroup"]
            Effect   = "Deny"
            Resource = "*"
          },
        ]
      })
    }
  }

  tags = merge(var.tags, var.iam_role_tags)
}

resource "aws_iam_role_policy_attachment" "this" {
  for_each = { for k, v in {
    AmazonEKSClusterPolicy         = local.create_outposts_local_cluster ? "${local.iam_role_policy_prefix}/AmazonEKSLocalOutpostClusterPolicy" : "${local.iam_role_policy_prefix}/AmazonEKSClusterPolicy",
    AmazonEKSVPCResourceController = "${local.iam_role_policy_prefix}/AmazonEKSVPCResourceController",
  } : k => v if local.create_iam_role }

  policy_arn = each.value
  role       = aws_iam_role.this[0].name
}

resource "aws_iam_role_policy_attachment" "additional" {
  for_each = { for k, v in var.iam_role_additional_policies : k => v if local.create_iam_role }

  policy_arn = each.value
  role       = aws_iam_role.this[0].name
}

resource "aws_iam_role_policy_attachment" "cluster_encryption" {
  count = local.create_iam_role && var.attach_cluster_encryption_policy && local.enable_cluster_encryption_config ? 1 : 0

  policy_arn = aws_iam_policy.cluster_encryption[0].arn
  role       = aws_iam_role.this[0].name
}

resource "aws_iam_policy" "cluster_encryption" {
  count = local.create_iam_role && var.attach_cluster_encryption_policy && local.enable_cluster_encryption_config ? 1 : 0

  name        = var.cluster_encryption_policy_use_name_prefix ? null : local.cluster_encryption_policy_name
  name_prefix = var.cluster_encryption_policy_use_name_prefix ? local.cluster_encryption_policy_name : null
  description = var.cluster_encryption_policy_description
  path        = var.cluster_encryption_policy_path

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ListGrants",
          "kms:DescribeKey",
        ]
        Effect   = "Allow"
        Resource = var.create_kms_key ? module.kms.key_arn : var.cluster_encryption_config.provider_key_arn
      },
    ]
  })

  tags = merge(var.tags, var.cluster_encryption_policy_tags)
}

################################################################################
# EKS Addons
################################################################################

data "aws_eks_addon_version" "this" {
  for_each = { for k, v in var.cluster_addons : k => v if local.create && !local.create_outposts_local_cluster }

  addon_name         = try(each.value.name, each.key)
  kubernetes_version = coalesce(var.cluster_version, aws_eks_cluster.this[0].version)
  most_recent        = try(each.value.most_recent, null)
}

resource "aws_eks_addon" "this" {
  for_each = { for k, v in var.cluster_addons : k => v if !try(v.before_compute, false) && local.create && !local.create_outposts_local_cluster }

  cluster_name = aws_eks_cluster.this[0].name
  addon_name   = try(each.value.name, each.key)

  addon_version               = coalesce(try(each.value.addon_version, null), data.aws_eks_addon_version.this[each.key].version)
  configuration_values        = try(each.value.configuration_values, null)
  preserve                    = try(each.value.preserve, true)
  resolve_conflicts_on_create = try(each.value.resolve_conflicts_on_create, "OVERWRITE")
  resolve_conflicts_on_update = try(each.value.resolve_conflicts_on_update, "OVERWRITE")
  service_account_role_arn    = try(each.value.service_account_role_arn, null)

  timeouts {
    create = try(each.value.timeouts.create, var.cluster_addons_timeouts.create, null)
    update = try(each.value.timeouts.update, var.cluster_addons_timeouts.update, null)
    delete = try(each.value.timeouts.delete, var.cluster_addons_timeouts.delete, null)
  }

  depends_on = [
    module.fargate_profile,
    module.eks_managed_node_group,
    module.self_managed_node_group,
  ]

  tags = merge(var.tags, try(each.value.tags, {}))
}

resource "aws_eks_addon" "before_compute" {
  for_each = { for k, v in var.cluster_addons : k => v if try(v.before_compute, false) && local.create && !local.create_outposts_local_cluster }

  cluster_name = aws_eks_cluster.this[0].name
  addon_name   = try(each.value.name, each.key)

  addon_version               = coalesce(try(each.value.addon_version, null), data.aws_eks_addon_version.this[each.key].version)
  configuration_values        = try(each.value.configuration_values, null)
  preserve                    = try(each.value.preserve, true)
  resolve_conflicts_on_create = try(each.value.resolve_conflicts_on_create, "OVERWRITE")
  resolve_conflicts_on_update = try(each.value.resolve_conflicts_on_update, "OVERWRITE")
  service_account_role_arn    = try(each.value.service_account_role_arn, null)

  timeouts {
    create = try(each.value.timeouts.create, var.cluster_addons_timeouts.create, null)
    update = try(each.value.timeouts.update, var.cluster_addons_timeouts.update, null)
    delete = try(each.value.timeouts.delete, var.cluster_addons_timeouts.delete, null)
  }

  tags = merge(var.tags, try(each.value.tags, {}))
}

################################################################################
# EKS Identity Provider
################################################################################

locals {
  idpc_backwards_compat_version = contains(["1.21", "1.22", "1.23", "1.24", "1.25", "1.26", "1.27", "1.28", "1.29"], coalesce(var.cluster_version, "1.30"))
  idpc_issuer_url               = local.idpc_backwards_compat_version ? try(aws_eks_cluster.this[0].identity[0].oidc[0].issuer, null) : null
}

resource "aws_eks_identity_provider_config" "this" {
  for_each = { for k, v in var.cluster_identity_providers : k => v if local.create && !local.create_outposts_local_cluster }

  cluster_name = aws_eks_cluster.this[0].name

  oidc {
    client_id                     = each.value.client_id
    groups_claim                  = lookup(each.value, "groups_claim", null)
    groups_prefix                 = lookup(each.value, "groups_prefix", null)
    identity_provider_config_name = try(each.value.identity_provider_config_name, each.key)
    # TODO - make argument explicitly required on next breaking change
    issuer_url      = try(each.value.issuer_url, local.idpc_issuer_url)
    required_claims = lookup(each.value, "required_claims", null)
    username_claim  = lookup(each.value, "username_claim", null)
    username_prefix = lookup(each.value, "username_prefix", null)
  }

  tags = merge(var.tags, try(each.value.tags, {}))
}

locals {
  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  default_update_config = {
    max_unavailable_percentage = 33
  }

  # Self-managed node group
  default_instance_refresh = {
    strategy = "Rolling"
    preferences = {
      min_healthy_percentage = 66
    }
  }

  kubernetes_network_config = try(aws_eks_cluster.this[0].kubernetes_network_config[0], {})
}

resource "time_sleep" "this" {
  count = var.create ? 1 : 0

  create_duration = var.dataplane_wait_duration

  triggers = {
    cluster_name         = aws_eks_cluster.this[0].name
    cluster_endpoint     = aws_eks_cluster.this[0].endpoint
    cluster_version      = aws_eks_cluster.this[0].version
    cluster_service_cidr = var.cluster_ip_family == "ipv6" ? try(local.kubernetes_network_config.service_ipv6_cidr, "") : try(local.kubernetes_network_config.service_ipv4_cidr, "")

    cluster_certificate_authority_data = aws_eks_cluster.this[0].certificate_authority[0].data
  }
}

################################################################################
# EKS IPV6 CNI Policy
################################################################################

data "aws_iam_policy_document" "cni_ipv6_policy" {
  count = var.create && var.create_cni_ipv6_iam_policy ? 1 : 0

  statement {
    sid = "AssignDescribe"
    actions = [
      "ec2:AssignIpv6Addresses",
      "ec2:DescribeInstances",
      "ec2:DescribeTags",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeInstanceTypes"
    ]
    resources = ["*"]
  }

  statement {
    sid       = "CreateTags"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:${local.partition}:ec2:*:*:network-interface/*"]
  }
}

resource "aws_iam_policy" "cni_ipv6_policy" {
  count = var.create && var.create_cni_ipv6_iam_policy ? 1 : 0
  name        = "AmazonEKS_CNI_IPv6_Policy"
  description = "IAM policy for EKS CNI to assign IPV6 addresses"
  policy      = data.aws_iam_policy_document.cni_ipv6_policy[0].json

  tags = var.tags
}

################################################################################
# Node Security Group
################################################################################

locals {
  node_sg_name   = coalesce(var.node_security_group_name, "${var.cluster_name}-node")
  create_node_sg = var.create && var.create_node_security_group

  node_security_group_id = local.create_node_sg ? aws_security_group.node[0].id : var.node_security_group_id

  node_security_group_rules = {
    ingress_cluster_443 = {
      description                   = "Cluster API to node groups"
      protocol                      = "tcp"
      from_port                     = 443
      to_port                       = 443
      type                          = "ingress"
      source_cluster_security_group = true
    }
    ingress_cluster_kubelet = {
      description                   = "Cluster API to node kubelets"
      protocol                      = "tcp"
      from_port                     = 10250
      to_port                       = 10250
      type                          = "ingress"
      source_cluster_security_group = true
    }
    ingress_self_coredns_tcp = {
      description = "Node to node CoreDNS"
      protocol    = "tcp"
      from_port   = 53
      to_port     = 53
      type        = "ingress"
      self        = true
    }
    ingress_self_coredns_udp = {
      description = "Node to node CoreDNS UDP"
      protocol    = "udp"
      from_port   = 53
      to_port     = 53
      type        = "ingress"
      self        = true
    }
  }

  node_security_group_recommended_rules = { for k, v in {
    ingress_nodes_ephemeral = {
      description = "Node to node ingress on ephemeral ports"
      protocol    = "tcp"
      from_port   = 1025
      to_port     = 65535
      type        = "ingress"
      self        = true
    }
    # metrics-server
    ingress_cluster_4443_webhook = {
      description                   = "Cluster API to node 4443/tcp webhook"
      protocol                      = "tcp"
      from_port                     = 4443
      to_port                       = 4443
      type                          = "ingress"
      source_cluster_security_group = true
    }
    # prometheus-adapter
    ingress_cluster_6443_webhook = {
      description                   = "Cluster API to node 6443/tcp webhook"
      protocol                      = "tcp"
      from_port                     = 6443
      to_port                       = 6443
      type                          = "ingress"
      source_cluster_security_group = true
    }
    # Karpenter
    ingress_cluster_8443_webhook = {
      description                   = "Cluster API to node 8443/tcp webhook"
      protocol                      = "tcp"
      from_port                     = 8443
      to_port                       = 8443
      type                          = "ingress"
      source_cluster_security_group = true
    }
    # ALB controller, NGINX
    ingress_cluster_9443_webhook = {
      description                   = "Cluster API to node 9443/tcp webhook"
      protocol                      = "tcp"
      from_port                     = 9443
      to_port                       = 9443
      type                          = "ingress"
      source_cluster_security_group = true
    }
    egress_all = {
      description      = "Allow all egress"
      protocol         = "-1"
      from_port        = 0
      to_port          = 0
      type             = "egress"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = var.cluster_ip_family == "ipv6" ? ["::/0"] : null
    }
  } : k => v if var.node_security_group_enable_recommended_rules }

  efa_security_group_rules = { for k, v in
    {
      ingress_all_self_efa = {
        description = "Node to node EFA"
        protocol    = "-1"
        from_port   = 0
        to_port     = 0
        type        = "ingress"
        self        = true
      }
      egress_all_self_efa = {
        description = "Node to node EFA"
        protocol    = "-1"
        from_port   = 0
        to_port     = 0
        type        = "egress"
        self        = true
      }
    } : k => v if var.enable_efa_support
  }
}

resource "aws_security_group" "node" {
  count = local.create_node_sg ? 1 : 0

  name        = var.node_security_group_use_name_prefix ? null : local.node_sg_name
  name_prefix = var.node_security_group_use_name_prefix ? "${local.node_sg_name}${var.prefix_separator}" : null
  description = var.node_security_group_description
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    {
      "Name"                                      = local.node_sg_name
      "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    },
    var.node_security_group_tags
  )

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "node" {
  for_each = { for k, v in merge(
    local.efa_security_group_rules,
    local.node_security_group_rules,
    local.node_security_group_recommended_rules,
    var.node_security_group_additional_rules,
  ) : k => v if local.create_node_sg }
  security_group_id = aws_security_group.node[0].id
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  type              = each.value.type
  description              = lookup(each.value, "description", null)
  cidr_blocks              = lookup(each.value, "cidr_blocks", null)
  ipv6_cidr_blocks         = lookup(each.value, "ipv6_cidr_blocks", null)
  prefix_list_ids          = lookup(each.value, "prefix_list_ids", [])
  self                     = lookup(each.value, "self", null)
  source_security_group_id = try(each.value.source_cluster_security_group, false) ? local.cluster_security_group_id : lookup(each.value, "source_security_group_id", null)
}

################################################################################
# Fargate Profile
################################################################################

module "fargate_profile" {
  source = "./modules/05-fargate-profile"
  for_each = { for k, v in var.fargate_profiles : k => v if var.create && !local.create_outposts_local_cluster }
  create = try(each.value.create, true)
  cluster_name      = time_sleep.this[0].triggers["cluster_name"]
  cluster_ip_family = var.cluster_ip_family
  name              = try(each.value.name, each.key)
  subnet_ids        = try(each.value.subnet_ids, var.fargate_profile_defaults.subnet_ids, var.subnet_ids)
  selectors         = try(each.value.selectors, var.fargate_profile_defaults.selectors, [])
  timeouts          = try(each.value.timeouts, var.fargate_profile_defaults.timeouts, {})
  create_iam_role               = try(each.value.create_iam_role, var.fargate_profile_defaults.create_iam_role, true)
  iam_role_arn                  = try(each.value.iam_role_arn, var.fargate_profile_defaults.iam_role_arn, null)
  iam_role_name                 = try(each.value.iam_role_name, var.fargate_profile_defaults.iam_role_name, null)
  iam_role_use_name_prefix      = try(each.value.iam_role_use_name_prefix, var.fargate_profile_defaults.iam_role_use_name_prefix, true)
  iam_role_path                 = try(each.value.iam_role_path, var.fargate_profile_defaults.iam_role_path, null)
  iam_role_description          = try(each.value.iam_role_description, var.fargate_profile_defaults.iam_role_description, "Fargate profile IAM role")
  iam_role_permissions_boundary = try(each.value.iam_role_permissions_boundary, var.fargate_profile_defaults.iam_role_permissions_boundary, null)
  iam_role_tags                 = try(each.value.iam_role_tags, var.fargate_profile_defaults.iam_role_tags, {})
  iam_role_attach_cni_policy    = try(each.value.iam_role_attach_cni_policy, var.fargate_profile_defaults.iam_role_attach_cni_policy, true)
  iam_role_additional_policies = lookup(each.value, "iam_role_additional_policies", lookup(var.fargate_profile_defaults, "iam_role_additional_policies", {}))
  create_iam_role_policy       = try(each.value.create_iam_role_policy, var.fargate_profile_defaults.create_iam_role_policy, true)
  iam_role_policy_statements   = try(each.value.iam_role_policy_statements, var.fargate_profile_defaults.iam_role_policy_statements, [])

  tags = merge(var.tags, try(each.value.tags, var.fargate_profile_defaults.tags, {}))
}

################################################################################
# EKS Managed Node Group
################################################################################

module "eks_managed_node_group" {
  source = "./modules/03-eks-managed-node-group"
  for_each = { for k, v in var.eks_managed_node_groups : k => v if var.create && !local.create_outposts_local_cluster }
  create = try(each.value.create, true)
  cluster_name    = time_sleep.this[0].triggers["cluster_name"]
  cluster_version = try(each.value.cluster_version, var.eks_managed_node_group_defaults.cluster_version, time_sleep.this[0].triggers["cluster_version"])
  name            = try(each.value.name, each.key)
  use_name_prefix = try(each.value.use_name_prefix, var.eks_managed_node_group_defaults.use_name_prefix, true)
  subnet_ids = try(each.value.subnet_ids, var.eks_managed_node_group_defaults.subnet_ids, var.subnet_ids)
  min_size     = try(each.value.min_size, var.eks_managed_node_group_defaults.min_size, 1)
  max_size     = try(each.value.max_size, var.eks_managed_node_group_defaults.max_size, 3)
  desired_size = try(each.value.desired_size, var.eks_managed_node_group_defaults.desired_size, 1)
  ami_id                         = try(each.value.ami_id, var.eks_managed_node_group_defaults.ami_id, "")
  ami_type                       = try(each.value.ami_type, var.eks_managed_node_group_defaults.ami_type, null)
  ami_release_version            = try(each.value.ami_release_version, var.eks_managed_node_group_defaults.ami_release_version, null)
  use_latest_ami_release_version = try(each.value.use_latest_ami_release_version, var.eks_managed_node_group_defaults.use_latest_ami_release_version, false)
  capacity_type        = try(each.value.capacity_type, var.eks_managed_node_group_defaults.capacity_type, null)
  disk_size            = try(each.value.disk_size, var.eks_managed_node_group_defaults.disk_size, null)
  force_update_version = try(each.value.force_update_version, var.eks_managed_node_group_defaults.force_update_version, null)
  instance_types       = try(each.value.instance_types, var.eks_managed_node_group_defaults.instance_types, null)
  labels               = try(each.value.labels, var.eks_managed_node_group_defaults.labels, null)
  remote_access = try(each.value.remote_access, var.eks_managed_node_group_defaults.remote_access, {})
  taints        = try(each.value.taints, var.eks_managed_node_group_defaults.taints, {})
  update_config = try(each.value.update_config, var.eks_managed_node_group_defaults.update_config, local.default_update_config)
  timeouts      = try(each.value.timeouts, var.eks_managed_node_group_defaults.timeouts, {})
  platform                   = try(each.value.platform, var.eks_managed_node_group_defaults.platform, "linux")
  cluster_endpoint           = try(time_sleep.this[0].triggers["cluster_endpoint"], "")
  cluster_auth_base64        = try(time_sleep.this[0].triggers["cluster_certificate_authority_data"], "")
  cluster_service_ipv4_cidr  = var.cluster_service_ipv4_cidr
  cluster_ip_family          = var.cluster_ip_family
  cluster_service_cidr       = try(time_sleep.this[0].triggers["cluster_service_cidr"], "")
  enable_bootstrap_user_data = try(each.value.enable_bootstrap_user_data, var.eks_managed_node_group_defaults.enable_bootstrap_user_data, false)
  pre_bootstrap_user_data    = try(each.value.pre_bootstrap_user_data, var.eks_managed_node_group_defaults.pre_bootstrap_user_data, "")
  post_bootstrap_user_data   = try(each.value.post_bootstrap_user_data, var.eks_managed_node_group_defaults.post_bootstrap_user_data, "")
  bootstrap_extra_args       = try(each.value.bootstrap_extra_args, var.eks_managed_node_group_defaults.bootstrap_extra_args, "")
  user_data_template_path    = try(each.value.user_data_template_path, var.eks_managed_node_group_defaults.user_data_template_path, "")
  cloudinit_pre_nodeadm      = try(each.value.cloudinit_pre_nodeadm, var.eks_managed_node_group_defaults.cloudinit_pre_nodeadm, [])
  cloudinit_post_nodeadm     = try(each.value.cloudinit_post_nodeadm, var.eks_managed_node_group_defaults.cloudinit_post_nodeadm, [])
  create_launch_template                 = try(each.value.create_launch_template, var.eks_managed_node_group_defaults.create_launch_template, true)
  use_custom_launch_template             = try(each.value.use_custom_launch_template, var.eks_managed_node_group_defaults.use_custom_launch_template, true)
  launch_template_id                     = try(each.value.launch_template_id, var.eks_managed_node_group_defaults.launch_template_id, "")
  launch_template_name                   = try(each.value.launch_template_name, var.eks_managed_node_group_defaults.launch_template_name, each.key)
  launch_template_use_name_prefix        = try(each.value.launch_template_use_name_prefix, var.eks_managed_node_group_defaults.launch_template_use_name_prefix, true)
  launch_template_version                = try(each.value.launch_template_version, var.eks_managed_node_group_defaults.launch_template_version, null)
  launch_template_default_version        = try(each.value.launch_template_default_version, var.eks_managed_node_group_defaults.launch_template_default_version, null)
  update_launch_template_default_version = try(each.value.update_launch_template_default_version, var.eks_managed_node_group_defaults.update_launch_template_default_version, true)
  launch_template_description            = try(each.value.launch_template_description, var.eks_managed_node_group_defaults.launch_template_description, "Custom launch template for ${try(each.value.name, each.key)} EKS managed node group")
  launch_template_tags                   = try(each.value.launch_template_tags, var.eks_managed_node_group_defaults.launch_template_tags, {})
  tag_specifications                     = try(each.value.tag_specifications, var.eks_managed_node_group_defaults.tag_specifications, ["instance", "volume", "network-interface"])
  ebs_optimized           = try(each.value.ebs_optimized, var.eks_managed_node_group_defaults.ebs_optimized, null)
  key_name                = try(each.value.key_name, var.eks_managed_node_group_defaults.key_name, null)
  disable_api_termination = try(each.value.disable_api_termination, var.eks_managed_node_group_defaults.disable_api_termination, null)
  kernel_id               = try(each.value.kernel_id, var.eks_managed_node_group_defaults.kernel_id, null)
  ram_disk_id             = try(each.value.ram_disk_id, var.eks_managed_node_group_defaults.ram_disk_id, null)
  block_device_mappings              = try(each.value.block_device_mappings, var.eks_managed_node_group_defaults.block_device_mappings, {})
  capacity_reservation_specification = try(each.value.capacity_reservation_specification, var.eks_managed_node_group_defaults.capacity_reservation_specification, {})
  cpu_options                        = try(each.value.cpu_options, var.eks_managed_node_group_defaults.cpu_options, {})
  credit_specification               = try(each.value.credit_specification, var.eks_managed_node_group_defaults.credit_specification, {})
  elastic_gpu_specifications         = try(each.value.elastic_gpu_specifications, var.eks_managed_node_group_defaults.elastic_gpu_specifications, {})
  elastic_inference_accelerator      = try(each.value.elastic_inference_accelerator, var.eks_managed_node_group_defaults.elastic_inference_accelerator, {})
  enclave_options                    = try(each.value.enclave_options, var.eks_managed_node_group_defaults.enclave_options, {})
  instance_market_options            = try(each.value.instance_market_options, var.eks_managed_node_group_defaults.instance_market_options, {})
  license_specifications             = try(each.value.license_specifications, var.eks_managed_node_group_defaults.license_specifications, {})
  metadata_options                   = try(each.value.metadata_options, var.eks_managed_node_group_defaults.metadata_options, local.metadata_options)
  enable_monitoring                  = try(each.value.enable_monitoring, var.eks_managed_node_group_defaults.enable_monitoring, true)
  enable_efa_support                 = try(each.value.enable_efa_support, var.eks_managed_node_group_defaults.enable_efa_support, false)
  create_placement_group             = try(each.value.create_placement_group, var.eks_managed_node_group_defaults.create_placement_group, false)
  placement                          = try(each.value.placement, var.eks_managed_node_group_defaults.placement, {})
  placement_group_az                 = try(each.value.placement_group_az, var.eks_managed_node_group_defaults.placement_group_az, null)
  placement_group_strategy           = try(each.value.placement_group_strategy, var.eks_managed_node_group_defaults.placement_group_strategy, "cluster")
  network_interfaces                 = try(each.value.network_interfaces, var.eks_managed_node_group_defaults.network_interfaces, [])
  maintenance_options                = try(each.value.maintenance_options, var.eks_managed_node_group_defaults.maintenance_options, {})
  private_dns_name_options           = try(each.value.private_dns_name_options, var.eks_managed_node_group_defaults.private_dns_name_options, {})
  create_iam_role               = try(each.value.create_iam_role, var.eks_managed_node_group_defaults.create_iam_role, true)
  iam_role_arn                  = try(each.value.iam_role_arn, var.eks_managed_node_group_defaults.iam_role_arn, null)
  iam_role_name                 = try(each.value.iam_role_name, var.eks_managed_node_group_defaults.iam_role_name, null)
  iam_role_use_name_prefix      = try(each.value.iam_role_use_name_prefix, var.eks_managed_node_group_defaults.iam_role_use_name_prefix, true)
  iam_role_path                 = try(each.value.iam_role_path, var.eks_managed_node_group_defaults.iam_role_path, null)
  iam_role_description          = try(each.value.iam_role_description, var.eks_managed_node_group_defaults.iam_role_description, "EKS managed node group IAM role")
  iam_role_permissions_boundary = try(each.value.iam_role_permissions_boundary, var.eks_managed_node_group_defaults.iam_role_permissions_boundary, null)
  iam_role_tags                 = try(each.value.iam_role_tags, var.eks_managed_node_group_defaults.iam_role_tags, {})
  iam_role_attach_cni_policy    = try(each.value.iam_role_attach_cni_policy, var.eks_managed_node_group_defaults.iam_role_attach_cni_policy, true)
  iam_role_additional_policies = lookup(each.value, "iam_role_additional_policies", lookup(var.eks_managed_node_group_defaults, "iam_role_additional_policies", {}))
  create_iam_role_policy       = try(each.value.create_iam_role_policy, var.eks_managed_node_group_defaults.create_iam_role_policy, true)
  iam_role_policy_statements   = try(each.value.iam_role_policy_statements, var.eks_managed_node_group_defaults.iam_role_policy_statements, [])
  create_schedule = try(each.value.create_schedule, var.eks_managed_node_group_defaults.create_schedule, true)
  schedules       = try(each.value.schedules, var.eks_managed_node_group_defaults.schedules, {})
  vpc_security_group_ids            = compact(concat([local.node_security_group_id], try(each.value.vpc_security_group_ids, var.eks_managed_node_group_defaults.vpc_security_group_ids, [])))
  cluster_primary_security_group_id = try(each.value.attach_cluster_primary_security_group, var.eks_managed_node_group_defaults.attach_cluster_primary_security_group, false) ? aws_eks_cluster.this[0].vpc_config[0].cluster_security_group_id : null

  tags = merge(var.tags, try(each.value.tags, var.eks_managed_node_group_defaults.tags, {}))
}

################################################################################
# Self Managed Node Group
################################################################################

module "self_managed_node_group" {
  source = "./modules/04-self-managed-node-group"

  for_each = { for k, v in var.self_managed_node_groups : k => v if var.create }
  create = try(each.value.create, true)
  cluster_name = time_sleep.this[0].triggers["cluster_name"]
  create_autoscaling_group = try(each.value.create_autoscaling_group, var.self_managed_node_group_defaults.create_autoscaling_group, true)
  name            = try(each.value.name, each.key)
  use_name_prefix = try(each.value.use_name_prefix, var.self_managed_node_group_defaults.use_name_prefix, true)
  availability_zones = try(each.value.availability_zones, var.self_managed_node_group_defaults.availability_zones, null)
  subnet_ids         = try(each.value.subnet_ids, var.self_managed_node_group_defaults.subnet_ids, var.subnet_ids)
  min_size                  = try(each.value.min_size, var.self_managed_node_group_defaults.min_size, 0)
  max_size                  = try(each.value.max_size, var.self_managed_node_group_defaults.max_size, 3)
  desired_size              = try(each.value.desired_size, var.self_managed_node_group_defaults.desired_size, 1)
  capacity_rebalance        = try(each.value.capacity_rebalance, var.self_managed_node_group_defaults.capacity_rebalance, null)
  min_elb_capacity          = try(each.value.min_elb_capacity, var.self_managed_node_group_defaults.min_elb_capacity, null)
  wait_for_elb_capacity     = try(each.value.wait_for_elb_capacity, var.self_managed_node_group_defaults.wait_for_elb_capacity, null)
  wait_for_capacity_timeout = try(each.value.wait_for_capacity_timeout, var.self_managed_node_group_defaults.wait_for_capacity_timeout, null)
  default_cooldown          = try(each.value.default_cooldown, var.self_managed_node_group_defaults.default_cooldown, null)
  default_instance_warmup   = try(each.value.default_instance_warmup, var.self_managed_node_group_defaults.default_instance_warmup, null)
  protect_from_scale_in     = try(each.value.protect_from_scale_in, var.self_managed_node_group_defaults.protect_from_scale_in, null)
  context                   = try(each.value.context, var.self_managed_node_group_defaults.context, null)
  target_group_arns         = try(each.value.target_group_arns, var.self_managed_node_group_defaults.target_group_arns, [])
  create_placement_group    = try(each.value.create_placement_group, var.self_managed_node_group_defaults.create_placement_group, false)
  placement_group           = try(each.value.placement_group, var.self_managed_node_group_defaults.placement_group, null)
  placement_group_az        = try(each.value.placement_group_az, var.self_managed_node_group_defaults.placement_group_az, null)
  health_check_type         = try(each.value.health_check_type, var.self_managed_node_group_defaults.health_check_type, null)
  health_check_grace_period = try(each.value.health_check_grace_period, var.self_managed_node_group_defaults.health_check_grace_period, null)
  ignore_failed_scaling_activities = try(each.value.ignore_failed_scaling_activities, var.self_managed_node_group_defaults.ignore_failed_scaling_activities, null)
  force_delete           = try(each.value.force_delete, var.self_managed_node_group_defaults.force_delete, null)
  force_delete_warm_pool = try(each.value.force_delete_warm_pool, var.self_managed_node_group_defaults.force_delete_warm_pool, null)
  termination_policies   = try(each.value.termination_policies, var.self_managed_node_group_defaults.termination_policies, [])
  suspended_processes    = try(each.value.suspended_processes, var.self_managed_node_group_defaults.suspended_processes, [])
  max_instance_lifetime  = try(each.value.max_instance_lifetime, var.self_managed_node_group_defaults.max_instance_lifetime, null)
  enabled_metrics         = try(each.value.enabled_metrics, var.self_managed_node_group_defaults.enabled_metrics, [])
  metrics_granularity     = try(each.value.metrics_granularity, var.self_managed_node_group_defaults.metrics_granularity, null)
  service_linked_role_arn = try(each.value.service_linked_role_arn, var.self_managed_node_group_defaults.service_linked_role_arn, null)
  initial_lifecycle_hooks     = try(each.value.initial_lifecycle_hooks, var.self_managed_node_group_defaults.initial_lifecycle_hooks, [])
  instance_maintenance_policy = try(each.value.instance_maintenance_policy, var.self_managed_node_group_defaults.instance_maintenance_policy, {})
  instance_refresh            = try(each.value.instance_refresh, var.self_managed_node_group_defaults.instance_refresh, local.default_instance_refresh)
  use_mixed_instances_policy  = try(each.value.use_mixed_instances_policy, var.self_managed_node_group_defaults.use_mixed_instances_policy, false)
  mixed_instances_policy      = try(each.value.mixed_instances_policy, var.self_managed_node_group_defaults.mixed_instances_policy, null)
  warm_pool                   = try(each.value.warm_pool, var.self_managed_node_group_defaults.warm_pool, {})
  delete_timeout         = try(each.value.delete_timeout, var.self_managed_node_group_defaults.delete_timeout, null)
  autoscaling_group_tags = try(each.value.autoscaling_group_tags, var.self_managed_node_group_defaults.autoscaling_group_tags, {})
  platform = try(each.value.platform, var.self_managed_node_group_defaults.platform, null)
  ami_type                 = try(each.value.ami_type, var.self_managed_node_group_defaults.ami_type, "AL2_x86_64")
  cluster_endpoint         = try(time_sleep.this[0].triggers["cluster_endpoint"], "")
  cluster_auth_base64      = try(time_sleep.this[0].triggers["cluster_certificate_authority_data"], "")
  cluster_service_cidr     = try(time_sleep.this[0].triggers["cluster_service_cidr"], "")
  cluster_ip_family        = var.cluster_ip_family
  pre_bootstrap_user_data  = try(each.value.pre_bootstrap_user_data, var.self_managed_node_group_defaults.pre_bootstrap_user_data, "")
  post_bootstrap_user_data = try(each.value.post_bootstrap_user_data, var.self_managed_node_group_defaults.post_bootstrap_user_data, "")
  bootstrap_extra_args     = try(each.value.bootstrap_extra_args, var.self_managed_node_group_defaults.bootstrap_extra_args, "")
  user_data_template_path  = try(each.value.user_data_template_path, var.self_managed_node_group_defaults.user_data_template_path, "")
  cloudinit_pre_nodeadm    = try(each.value.cloudinit_pre_nodeadm, var.self_managed_node_group_defaults.cloudinit_pre_nodeadm, [])
  cloudinit_post_nodeadm   = try(each.value.cloudinit_post_nodeadm, var.self_managed_node_group_defaults.cloudinit_post_nodeadm, [])
  create_launch_template                 = try(each.value.create_launch_template, var.self_managed_node_group_defaults.create_launch_template, true)
  launch_template_id                     = try(each.value.launch_template_id, var.self_managed_node_group_defaults.launch_template_id, "")
  launch_template_name                   = try(each.value.launch_template_name, var.self_managed_node_group_defaults.launch_template_name, each.key)
  launch_template_use_name_prefix        = try(each.value.launch_template_use_name_prefix, var.self_managed_node_group_defaults.launch_template_use_name_prefix, true)
  launch_template_version                = try(each.value.launch_template_version, var.self_managed_node_group_defaults.launch_template_version, null)
  launch_template_default_version        = try(each.value.launch_template_default_version, var.self_managed_node_group_defaults.launch_template_default_version, null)
  update_launch_template_default_version = try(each.value.update_launch_template_default_version, var.self_managed_node_group_defaults.update_launch_template_default_version, true)
  launch_template_description            = try(each.value.launch_template_description, var.self_managed_node_group_defaults.launch_template_description, "Custom launch template for ${try(each.value.name, each.key)} self managed node group")
  launch_template_tags                   = try(each.value.launch_template_tags, var.self_managed_node_group_defaults.launch_template_tags, {})
  tag_specifications                     = try(each.value.tag_specifications, var.self_managed_node_group_defaults.tag_specifications, ["instance", "volume", "network-interface"])

  ebs_optimized   = try(each.value.ebs_optimized, var.self_managed_node_group_defaults.ebs_optimized, null)
  ami_id          = try(each.value.ami_id, var.self_managed_node_group_defaults.ami_id, "")
  cluster_version = try(each.value.cluster_version, var.self_managed_node_group_defaults.cluster_version, time_sleep.this[0].triggers["cluster_version"])
  instance_type   = try(each.value.instance_type, var.self_managed_node_group_defaults.instance_type, "m6i.large")
  key_name        = try(each.value.key_name, var.self_managed_node_group_defaults.key_name, null)

  disable_api_termination              = try(each.value.disable_api_termination, var.self_managed_node_group_defaults.disable_api_termination, null)
  instance_initiated_shutdown_behavior = try(each.value.instance_initiated_shutdown_behavior, var.self_managed_node_group_defaults.instance_initiated_shutdown_behavior, null)
  kernel_id                            = try(each.value.kernel_id, var.self_managed_node_group_defaults.kernel_id, null)
  ram_disk_id                          = try(each.value.ram_disk_id, var.self_managed_node_group_defaults.ram_disk_id, null)

  block_device_mappings              = try(each.value.block_device_mappings, var.self_managed_node_group_defaults.block_device_mappings, {})
  capacity_reservation_specification = try(each.value.capacity_reservation_specification, var.self_managed_node_group_defaults.capacity_reservation_specification, {})
  cpu_options                        = try(each.value.cpu_options, var.self_managed_node_group_defaults.cpu_options, {})
  credit_specification               = try(each.value.credit_specification, var.self_managed_node_group_defaults.credit_specification, {})
  elastic_gpu_specifications         = try(each.value.elastic_gpu_specifications, var.self_managed_node_group_defaults.elastic_gpu_specifications, {})
  elastic_inference_accelerator      = try(each.value.elastic_inference_accelerator, var.self_managed_node_group_defaults.elastic_inference_accelerator, {})
  enclave_options                    = try(each.value.enclave_options, var.self_managed_node_group_defaults.enclave_options, {})
  hibernation_options                = try(each.value.hibernation_options, var.self_managed_node_group_defaults.hibernation_options, {})
  instance_requirements              = try(each.value.instance_requirements, var.self_managed_node_group_defaults.instance_requirements, {})
  instance_market_options            = try(each.value.instance_market_options, var.self_managed_node_group_defaults.instance_market_options, {})
  license_specifications             = try(each.value.license_specifications, var.self_managed_node_group_defaults.license_specifications, {})
  metadata_options                   = try(each.value.metadata_options, var.self_managed_node_group_defaults.metadata_options, local.metadata_options)
  enable_monitoring                  = try(each.value.enable_monitoring, var.self_managed_node_group_defaults.enable_monitoring, true)
  enable_efa_support                 = try(each.value.enable_efa_support, var.self_managed_node_group_defaults.enable_efa_support, false)
  network_interfaces                 = try(each.value.network_interfaces, var.self_managed_node_group_defaults.network_interfaces, [])
  placement                          = try(each.value.placement, var.self_managed_node_group_defaults.placement, {})
  maintenance_options                = try(each.value.maintenance_options, var.self_managed_node_group_defaults.maintenance_options, {})
  private_dns_name_options           = try(each.value.private_dns_name_options, var.self_managed_node_group_defaults.private_dns_name_options, {})
  create_iam_instance_profile   = try(each.value.create_iam_instance_profile, var.self_managed_node_group_defaults.create_iam_instance_profile, true)
  iam_instance_profile_arn      = try(each.value.iam_instance_profile_arn, var.self_managed_node_group_defaults.iam_instance_profile_arn, null)
  iam_role_name                 = try(each.value.iam_role_name, var.self_managed_node_group_defaults.iam_role_name, null)
  iam_role_use_name_prefix      = try(each.value.iam_role_use_name_prefix, var.self_managed_node_group_defaults.iam_role_use_name_prefix, true)
  iam_role_path                 = try(each.value.iam_role_path, var.self_managed_node_group_defaults.iam_role_path, null)
  iam_role_description          = try(each.value.iam_role_description, var.self_managed_node_group_defaults.iam_role_description, "Self managed node group IAM role")
  iam_role_permissions_boundary = try(each.value.iam_role_permissions_boundary, var.self_managed_node_group_defaults.iam_role_permissions_boundary, null)
  iam_role_tags                 = try(each.value.iam_role_tags, var.self_managed_node_group_defaults.iam_role_tags, {})
  iam_role_attach_cni_policy    = try(each.value.iam_role_attach_cni_policy, var.self_managed_node_group_defaults.iam_role_attach_cni_policy, true)
  iam_role_additional_policies = lookup(each.value, "iam_role_additional_policies", lookup(var.self_managed_node_group_defaults, "iam_role_additional_policies", {}))
  create_iam_role_policy       = try(each.value.create_iam_role_policy, var.self_managed_node_group_defaults.create_iam_role_policy, true)
  iam_role_policy_statements   = try(each.value.iam_role_policy_statements, var.self_managed_node_group_defaults.iam_role_policy_statements, [])
  create_access_entry = try(each.value.create_access_entry, var.self_managed_node_group_defaults.create_access_entry, true)
  iam_role_arn        = try(each.value.iam_role_arn, var.self_managed_node_group_defaults.iam_role_arn, null)
  create_schedule = try(each.value.create_schedule, var.self_managed_node_group_defaults.create_schedule, true)
  schedules       = try(each.value.schedules, var.self_managed_node_group_defaults.schedules, {})
  vpc_security_group_ids            = compact(concat([local.node_security_group_id], try(each.value.vpc_security_group_ids, var.self_managed_node_group_defaults.vpc_security_group_ids, [])))
  cluster_primary_security_group_id = try(each.value.attach_cluster_primary_security_group, var.self_managed_node_group_defaults.attach_cluster_primary_security_group, false) ? aws_eks_cluster.this[0].vpc_config[0].cluster_security_group_id : null
  tags = merge(var.tags, try(each.value.tags, var.self_managed_node_group_defaults.tags, {}))
}

