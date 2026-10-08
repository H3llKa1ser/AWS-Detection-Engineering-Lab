# ---------------------------------------------------------------------------
# Minimal, isolated lab VPC to attach network telemetry to.
#
# Deliberately has no internet gateway or NAT: it costs nothing to run and the
# only things inside it are what you put there. DNS still works, because the
# Route 53 Resolver answers every VPC at the link-local address, so DNS query
# logging and DNS-based detections are fully exercisable here.
# ---------------------------------------------------------------------------

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "lab" {
  cidr_block           = var.cidr_block
  enable_dns_support   = true
  enable_dns_hostnames = true

  assign_generated_ipv6_cidr_block = var.enable_ipv6

  tags = { Name = "${var.name_prefix}-lab-vpc" }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.lab.id
  cidr_block        = cidrsubnet(var.cidr_block, 8, 1)
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = { Name = "${var.name_prefix}-lab-private" }
}

# Strip every rule from the VPC's default security group so it stays compliant
# with the vpc-default-sg-closed Config rule this lab itself deploys.
resource "aws_default_security_group" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${var.name_prefix}-default-sg-closed" }
}
