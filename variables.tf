variable "aws_region" {
  description = "AWS region to deploy Kali lab into"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type for Kali lab"
  type        = string
  default     = "t3.micro"
}

variable "key_name" {
  description = "EC2 key pair name to use for SSH access"
  type        = string
}

variable "root_volume_size" {
  description = "Root EBS volume size for Kali"
  type        = number
  default     = 40
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed to SSH into Kali (e.g. your home IP /32)"
  type        = string
}

variable "allowed_web_cidr" {
  description = "CIDR block allowed to access Web UI (e.g. your home IP /32)"
  type        = string
}

variable "tailscale_authkey" {
  description = <<EOT
Tailscale auth key used during EC2 boot to auto-enroll the instance.
Generate at: https://login.tailscale.com/admin/settings/keys
Must be kept secret and should NOT be placed in version control.
EOT
  type        = string
  sensitive   = true
}
