provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.name_prefix
      ManagedBy   = "terraform"
      Environment = "lab"
      Repo        = "AWS-Detection-Engineering-Lab"
    }
  }
}

provider "awscc" {
  region = var.aws_region
}
