########################################
# Data source: Kali Linux AMI
########################################


########################################
# Security Group: kali-sg
########################################

resource "aws_security_group" "kali_sg" {
  name        = "kali-sg"
  description = "Security group for Kali EC2 lab instance"
  vpc_id      = aws_vpc.kali_vpc.id

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
# Network: VPC, Subnet, IGW, Route Table
########################################

# New isolated VPC for the Kali lab
resource "aws_vpc" "kali_vpc" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "kali-lab-vpc"
  }
}

# Public subnet so the instance can reach the internet (for Tailscale)
resource "aws_subnet" "kali_subnet" {
  vpc_id                  = aws_vpc.kali_vpc.id
  cidr_block              = "10.42.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name = "kali-lab-subnet"
  }
}

# Internet gateway for outbound access
resource "aws_internet_gateway" "kali_igw" {
  vpc_id = aws_vpc.kali_vpc.id

  tags = {
    Name = "kali-lab-igw"
  }
}

# Route table for the public subnet
resource "aws_route_table" "kali_rt" {
  vpc_id = aws_vpc.kali_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.kali_igw.id
  }

  tags = {
    Name = "kali-lab-rt"
  }
}

# Associate the route table with the subnet
resource "aws_route_table_association" "kali_rta" {
  subnet_id      = aws_subnet.kali_subnet.id
  route_table_id = aws_route_table.kali_rt.id
}

########################################
# EC2 Instance: kali-lab-01
########################################

resource "aws_instance" "kali_lab" {
  ami                         = "data.aws_ami.kali.id"     <-- Was this replaced; if so, delete this extra text.
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.kali_subnet.id
  vpc_security_group_ids      = [aws_security_group.kali_sg.id]
  associate_public_ip_address = true
  key_name                    = var.key_name

  user_data = <<-EOF
    #!/bin/bash
    set -eux

    # Make sure we don't get stuck on interactive prompts
    export DEBIAN_FRONTEND=noninteractive

    # Basic updates & tools
    apt-get update -y
    apt-get install -y curl ca-certificates gnupg apt-transport-https

    # Add Tailscale's Debian (bookworm) repo + key
    curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg \
      | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null

    curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list \
      | tee /etc/apt/sources.list.d/tailscale.list >/dev/null

    apt-get update -y
    apt-get install -y tailscale

    # Enable and start the daemon
    systemctl enable tailscaled
    systemctl start tailscaled

    # Give it a second to settle
    sleep 5

    # Bring the node into your tailnet.
    # NOTE: use a reusable/preauthorized auth key from the Tailscale admin UI.
    tailscale up \
      --auth-key=${var.tailscale_authkey} \
      --ssh \
      --hostname=kali-lab-$(hostname) \
      --advertise-tags=tag:kali \
      2>&1 | tee /var/log/tailscale-up.log

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
  description = "Hard-coded AMI used for Kali"
  value       = "ami-014f91f72b49fb01b"
}
