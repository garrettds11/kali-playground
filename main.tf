########################################
# Data source: Kali Linux AMI
########################################
# NOTE:
#   - This filter is an example that often works for Marketplace-based AMIs.
#   - You may need to adjust `owners` and/or `filter` values after you pick
#     the exact Marketplace product you want.
########################################

data "aws_ami" "kali" {
  most_recent = true

  # For Marketplace AMIs, owners is usually "aws-marketplace".
  owners = ["aws-marketplace"]

  # You will likely need to tweak the name filter after selecting your product.
  # In the console, once you choose a Kali AMI, check its "AMI ID" and "Name".
  # Then adapt `name` or another filter to match it.
  filter {
    name   = "name"
    values = ["kali-linux-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

########################################
# Security Group: kali-sg
########################################

resource "aws_security_group" "kali_sg" {
  name        = "kali-sg"
  description = "Security group for Kali EC2 lab instance"
  vpc_id      = data.aws_vpc.default.id

  # SSH inbound
  ingress {
    description = "SSH from trusted CIDR"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  # Web UI inbound (e.g. for noVNC, HTTP interface, etc.)
  ingress {
    description = "Web UI from trusted CIDR"
    from_port   = 8888
    to_port     = 8888
    protocol    = "tcp"
    cidr_blocks = [var.allowed_web_cidr]
  }

  # Egress - allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "kali-sg"
  }
}

########################################
# Default VPC + Subnet (simple case)
########################################

data "aws_vpc" "default" {
  default = true
}

data "aws_subnet_ids" "default" {
  vpc_id = data.aws_vpc.default.id
}

# Just pick the first default subnet for simplicity
locals {
  kali_subnet_id = element(data.aws_subnet_ids.default.ids, 0)
}

########################################
# EC2 Instance: kali-lab-01
########################################

resource "aws_instance" "kali_lab" {
  ami                    = data.aws_ami.kali.id     <-- Was this replaced; if so, delete this extra text.
  instance_type          = var.instance_type
  subnet_id              = local.kali_subnet_id
  vpc_security_group_ids = [aws_security_group.kali_sg.id]
  associate_public_ip_address = true
  key_name               = var.key_name

  user_data = <<-EOF
    #!/bin/bash
    set -eux

    # Ensure system is updated enough to install new packages
    apt-get update -y

    # Install curl + dependencies
    apt-get install -y curl ca-certificates gnupg

    # Add Tailscale repo + key (Debian/Kali)
    curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg \
      | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null

    curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list \
      | tee /etc/apt/sources.list.d/tailscale.list

    apt-get update -y
    apt-get install -y tailscale

    # Bring Tailscale online using a preauthorized key
    tailscale up --authkey=${tailscale_authkey} \
                 --ssh \
                 --hostname=kali-lab-$(hostname)

    # Persist Tailscale state
    systemctl enable tailscaled
    systemctl start tailscaled
  EOF

  root_block_device {
    volume_size = var.root_volume_size
    volume_type = "gp3"
    encrypted   = true
  }

  tags = {
    Name = "kali-lab-01"
    Role = "kali-lab"
  }
}

########################################
# Outputs
########################################

output "kali_public_ip" {
  description = "Public IP of the Kali lab instance"
  value       = aws_instance.kali_lab.public_ip
}

output "kali_public_dns" {
  description = "Public DNS of the Kali lab instance"
  value       = aws_instance.kali_lab.public_dns
}

output "kali_ami_id" {
  description = "AMI ID used for the Kali instance"
  value       = data.aws_ami.kali.id
}
