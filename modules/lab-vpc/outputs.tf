output "vpc_id" {
  value = aws_vpc.lab.id
}

output "private_subnet_id" {
  value = aws_subnet.private.id
}

output "ipv6_cidr_block" {
  value = aws_vpc.lab.ipv6_cidr_block
}
