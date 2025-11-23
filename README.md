# Penetration test from AWS
## `w/ Kali + Tailscale + Flask + Node`

===============================================================

> #### ASSUMPTIONS:
> 1. You have an AWS account.
> 2. You are familiar with AWS EC2.
> 3. You can SSH to a remote host if needed.
> 4. AWS CLI is installed.
> 5. An AWS CLI profile is configured for authentication.
> 6. You can host a vulnerable server from your own device.
> 7. You can install and run python or node.js.
>
> [ https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html ]
> 
> [ https://www.geeksforgeeks.org/ethical-hacking/kali-linux-tutorial/ ]
>
> [ https://www.kali.org/ ]
> [ https://tailscale.com/ ]

===============================================================

> #### TABLE OF CONTENTS:
> 1. Tailscale Setup
> 2. Kali installation on EC2 via Terraform
> 3. Connect Kali <:> Laptop

===============================================================

---

## 1. Tailscale Setup

### Sign up for Tailscale
* Go to Tailscale’s site: `https://tailscale.com/download`
* Sign up for a free account.
* Create your tailnet (default is fine).
* Create a key: `https://login.tailscale.com/admin/settings/keys`

### Install Tailscale on your laptop

* Download Tailscale for Windows.
* Install it and sign in with the same account you used above.
* Once running, you’ll see your tailnet devices in the UI.

> Your laptop will also get a tailnet IP like `100.a.b.c`.

### Pre/Post-install & run Tailscale on Kali
* Terraform will auto-install Tailscale after bringing up the instance.
* You can `ssh` to Kali after it's up to manually install Tailscale, or not use it at all.
---
* ! NOTE !
* **If you don't want to pre-install Tailscale**, do these 2 steps:

---

###### Step 1
> **REMOVE** this variable from `variables.tf`.

```
variable "tailscale_authkey" {
  description = <<EOT
Tailscale auth key used during EC2 boot to auto-enroll the instance.
Generate at: https://login.tailscale.com/admin/settings/keys
Must be kept secret and should NOT be placed in version control.
EOT
  type        = string
  sensitive   = true
}
```
###### Step 2
> **REPLACE** this whole section from within `main.tf`.

```
########################################
# EC2 Instance: kali-lab-01
########################################

resource "aws_instance" "kali_lab" {
  ami                    = data.aws_ami.kali.id
  instance_type          = var.instance_type
  subnet_id              = local.kali_subnet_id
  vpc_security_group_ids = [aws_security_group.kali_sg.id]

  associate_public_ip_address = true
  key_name                    = var.key_name

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
```

===============================================================

---

## 2. Kali installation on EC2 via Terraform

### Create Terraform files

Save and drop these files into a project folder.
* `providers.tf`
* `variables.tf`
* `main.tf`
* `terraform.tfvars`

---

> SAVE_FILE://providers.tf

```
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}
```

---

> SAVE_FILE://variables.tf

```
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
```

---

> SAVE_FILE://main.tf

```
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
```

---

> SAVE_FILE://terraform.tfvars

```
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
```

===============================================================

---

### => main.tf

**Update the Kali AMI** in `main.tf`

```
########################################
# EC2 Instance: kali-lab-01
########################################

resource "aws_instance" "kali_lab" {
  ami                    = data.aws_ami.kali.id     <-- Was this replaced; if so, delete this extra text.
```

---

### => terraform.tfvars

**Update authorized IPs** for `ssh` and `web` in Kali.

```
# Replace with your real IP/CIDR:
# e.g. if your IP is 98.76.54.32, then "98.76.54.32/32"
allowed_ssh_cidr = "your.pub.ip.addr/32"
allowed_web_cidr = "your.pub.ip.addr/32"
```

---

**Update the Tailscale key**

Replace the terraform `tailscale_authkey` variable with your real key in `file://terraform.tfvars` also.

`tailscale_authkey = "tskey-auth-ABC123..."`

>**Or export the key** as a temporary variable before running terraform (RECOMMENDED)

`export tailscale_authkey="tskey-auth-ABC123..."`

---

### Run Terraform

```
export tailscale_authkey="..."
terraform apply
```

===============================================================

## 3. Connect `Kali <:> Laptop`

**Access your Kali box**

`ssh root@<tailscale-ip>`

 -- or --

`ssh kali@<tailscale-ip>`

---

#### Run a vulnerable Flask app

* Create a virtual environment
```
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
# source venv/bin/activate
```
* Install Flask: `pip install Flask`
* Run the app: `python vulnapp.py`

```
[*] Database initialized at .../vulnapp.db
 * Serving Flask app 'vulnapp'
 * Debug mode: on
 * Running on http://0.0.0.0:5000
```

* Visit it locally: `http://localhost:5000`

#### Launch attacks from Kali

* Connect remotely:
```
# On Kali EC2
curl http://<your-laptop-tailscale-ip>:5000/`
# your laptop's Tailscale IP
ping 100.a.b.c
curl http://100.a.b.c:5000/
```

> Your Kali tools (nmap, Burp, sqlmap, etc.) can now target 100.a.b.c directly:

```
nmap -sV 100.a.b.c -p 5000

# SQLi lab: 
http://<tailscale-ip>:5000/search?q=' OR 1=1--

# XSS lab: 
http://<tailscale-ip>:5000/comments
```

---

#### Run a vulnerable Node app

* Install & run from the folder with package.json and app.js:
```
# 1) Install dependencies
npm install

# 2) Run app
npm start
# or during development with auto-reload:
# npx nodemon app.js

[*] Initializing SQLite database at .../vulnapp-node.db
[*] VulnApp Node listening on http://0.0.0.0:5000
[*] Do NOT expose this to the internet.

```

* Visit it locally: `http://localhost:5000`

#### Launch attacks from Kali

* Connect remotely:
```
# On Kali EC2
curl http://<your-laptop-tailscale-ip>:5000/`
# your laptop's Tailscale IP
ping 100.a.b.c
curl http://100.a.b.c:5000/
```

> Your Kali tools (nmap, Burp, sqlmap, etc.) can now target 100.a.b.c directly:

```
nmap -sV 100.a.b.c -p 5000

# SQL Injection 
http://<tailscale-ip>:5000/search?q=' OR 1=1--
# This returns all user records, including plaintext passwords.

# Login SQLi
http://<laptop-tailscale-ip>:5000/login
# Attack example:
Username: ' OR '1'='1
Password: anything
# Because '1'='1' is always true, the database returns all users.

# Search SQLi
http://<laptop-tailscale-ip>:5000/search

# Stored XSS, post comment
http://<laptop-tailscale-ip>:5000/comments
# comment:
<script>alert('This could launch a keylogger, cookie-stealer, or worse! Impact: Stored XSS persists across page loads; Every viewer gets the payload; Great for practicing real browser-based exploitation and Burp Suite interception.');</script>

# File upload: 
http://<laptop-tailscale-ip>:5000/upload
# Upload a file called evil.html:
<h1>You have been pwned</h1>
<script>alert("This could launch a keylogger, cookie-stealer, or worse! Impact: uploaded HTML/JS page renders in the browser. If you upload a .js file, it executes as JavaScript. If you upload an image, it displays. If you upload a large file, it stores it.
You can host malware files (safe for lab use). You can create a browser-based XSS or phishing page. You can upload web shells (in PHP servers — Node won’t execute PHP, but still demonstrates danger). You can use it as a “pivot” to attack users who visit the URL.")</script>
```

===============================================================

> You can also target the Kali box from your laptop using its tailnet IP (100.x.y.z) if you later run a web UI (e.g. on port 8080) without exposing 8888 to the Internet at all. Just let Tailscale carry that traffic.

# END

===============================================================

---

> ALTERNATE ENDING:

## Install Tailscale manually via SSH

**SSH into your new Kali EC2:**

`ssh -i /path/to/kali-lab-keypair.pem kali@<kali_public_ip>`

---

**Then install Tailscale (Debian/Kali commands):**

```
# Import Tailscale's signing key and repo
curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg | \
  sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null

curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list | \
  sudo tee /etc/apt/sources.list.d/tailscale.list

sudo apt update
sudo apt install -y tailscale
```

> (If Kali’s base is a different codename than bookworm when you do this, just swap the codename for whatever `lsb_release -c` shows.)

---

**Then bring it up:**

`sudo tailscale up`

>This will spit out a URL. Copy that URL into your browser, log into Tailscale, and approve the new device. After it’s connected:

`tailscale ip`

> You’ll see something like `100.x.y.z` — that’s the Kali machine’s tailnet IP.

---
