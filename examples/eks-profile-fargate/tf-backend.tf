terraform {
  backend "s3" {
    bucket = "quarks-labs"
    key = "eks-profile-fargate/terraform.tfstate"
    region = "us-east-1"
  }
}