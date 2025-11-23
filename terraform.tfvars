aws_region       = "us-east-1"
instance_type    = "t3.micro"
key_name         = "kali-ssh-keypair"
root_volume_size = 40

# Replace with your real IP/CIDR:
# e.g. if your IP is 98.76.54.32, then "98.76.54.32/32"
allowed_ssh_cidr = "your.pub.ip.addr/32"
allowed_web_cidr = "your.pub.ip.addr/32"

# Run this...
# export tailscale_authkey="tskey-auth-ABC123..."
# ...before
# terraform apply

# Or save the tailscale key here
# tailscale_authkey = "tskey-auth-ABC123..."