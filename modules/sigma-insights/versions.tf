terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
    # Log alarms (AWS::CloudWatch::LogAlarm) are not in hashicorp/aws 6.x; the
    # Cloud Control provider exposes them from the CloudFormation schema.
    awscc = {
      source = "hashicorp/awscc"
    }
  }
}
