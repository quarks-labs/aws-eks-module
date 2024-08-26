terraform {
  backend "s3" {
    bucket = "quarks-labs"
    key = "aws-eks-module/terraform.tfstate"
  }
}