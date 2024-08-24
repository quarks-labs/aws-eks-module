variable "tags" {
  description = "Tags"
  type = map(any)
}

variable "name" {
  type = string
  description = "Name of VPC"
}

variable "vpc_cidr" {
  type = string
  description = "CIDR VPC"
}

variable "region" {
  type = string
  description = "Region of VPC"
}