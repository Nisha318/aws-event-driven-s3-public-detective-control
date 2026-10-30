terraform {
  required_version = "1.13.4"

  cloud {

    organization = "AnvilTeam"

    workspaces {
      name = "aws-event-driven-s3-public-detective-control"
    }
  }
}

provider "aws" {
  region = var.aws_region
}
