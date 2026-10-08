# ---------------------------------------------------------------------------
# Opt-in traffic generator (disabled by default)
#
# One small instance in the isolated lab VPC that runs src/dnsgen.py as a
# systemd service. Hardened: no ingress, no public IP, no instance role,
# IMDSv2 required, encrypted root volume. It exists only to produce telemetry.
# ---------------------------------------------------------------------------

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_security_group" "generator" {
  name        = "${var.name_prefix}-traffic-generator"
  description = "Traffic generator: no ingress, egress for DNS only"
  vpc_id      = var.vpc_id

  egress {
    description = "DNS to Route 53 Resolver"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["169.254.169.253/32"]
  }
}

locals {
  user_data = <<-EOT
    #!/bin/bash
    set -euo pipefail
    mkdir -p /opt/detlab
    base64 -d > /opt/detlab/dnsgen.py <<'B64'
    ${base64encode(file("${path.module}/src/dnsgen.py"))}
    B64
    chmod 0755 /opt/detlab/dnsgen.py

    cat > /etc/systemd/system/detlab-dnsgen.service <<'UNIT'
    [Unit]
    Description=Detection lab DNS traffic generator
    After=network-online.target

    [Service]
    ExecStart=/usr/bin/python3 /opt/detlab/dnsgen.py
    Restart=always
    DynamicUser=yes

    [Install]
    WantedBy=multi-user.target
    UNIT

    systemctl daemon-reload
    systemctl enable --now detlab-dnsgen.service
  EOT
}

resource "aws_instance" "generator" {
  ami                         = data.aws_ssm_parameter.al2023.value
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.generator.id]
  associate_public_ip_address = false
  user_data                   = local.user_data
  user_data_replace_on_change = true

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
  }

  tags = { Name = "${var.name_prefix}-traffic-generator" }
}
