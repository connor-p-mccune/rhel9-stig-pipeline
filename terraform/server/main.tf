# =============================================================================
# terraform/server/main.tf
#
# WHAT THIS FILE DOES, IN PLAIN LANGUAGE
# --------------------------------------
# It creates ONE Red Hat Enterprise Linux 9 server on AWS -- the test subject
# we will scan, harden, and measure. It also creates the two things that server
# needs in order to be reachable safely:
#   - a key pair       (the SSH key that proves it is you when you log in)
#   - a security group (a firewall that only lets YOUR address reach port 22)
#
# WHY t3.small AND NOT THE CHEAPER t3.micro
# -----------------------------------------
# t3.small has 2 GB of RAM; t3.micro has 1 GB. The OpenSCAP scanner loads the
# entire STIG rule set into memory at once, and the Ansible playbook it
# generates is thousands of tasks long. On a 1 GB machine, Linux runs out of
# memory partway through and kills those processes -- which shows up as a
# mysterious crash or a hang, not as a clear "out of memory" message. The extra
# cent or so per hour buys you scans and remediation runs that actually finish.
#
# WHY A 20 GB DISK AND NOT THE 10 GB DEFAULT
# ------------------------------------------
# The STIG requires verbose audit logging (auditd) and wants those logs kept
# rather than rotated away quickly -- there are even rules about reserving free
# space so a full disk cannot silently stop the logging. 20 GB gives the audit
# logs, the SCAP content package, and the scan result files room to live
# without the disk filling up in the middle of the project.
# =============================================================================

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.0"
    }
  }
}

# No default on purpose. You must state the profile every time, so you can
# never accidentally build into the wrong AWS account.
variable "aws_profile" {
  description = "Name of the AWS CLI profile Terraform should use. For this project: nist-admin"
  type        = string
}

provider "aws" {
  region  = "us-east-1"
  profile = var.aws_profile
}

# -----------------------------------------------------------------------------
# Find the newest official RHEL 9 image.
# owners = ["309956199498"] is Red Hat's own AWS account ID. Pinning to it means
# we can never accidentally launch some stranger's "RHEL-flavored" image that
# happens to match the name pattern.
# -----------------------------------------------------------------------------
data "aws_ami" "rhel9" {
  most_recent = true
  owners      = ["309956199498"]

  filter {
    name   = "name"
    values = ["RHEL-9.*_HVM-*-x86_64-*-Hourly*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# -----------------------------------------------------------------------------
# Ask AWS what our current public internet address is. The response comes back
# with a trailing newline, so chomp() strips it -- without that, the security
# group rule below would be malformed.
# -----------------------------------------------------------------------------
data "http" "myip" {
  url = "https://checkip.amazonaws.com"
}

# Every AWS account comes with a default VPC (a private network) in each region.
# We use it rather than building our own, because this is a single throwaway lab
# server and a custom network would be complexity with no security benefit here.
data "aws_vpc" "default" {
  default = true
}

# -----------------------------------------------------------------------------
# The SSH key pair. Terraform uploads only the PUBLIC half (.pub). The private
# half never leaves your laptop -- that is the whole point of key-based login.
# -----------------------------------------------------------------------------
resource "aws_key_pair" "stig_lab" {
  key_name   = "stig-lab"
  public_key = file(pathexpand("~/.ssh/stig-lab.pub"))

  tags = {
    Name    = "stig-lab"
    Project = "rhel9-stig-pipeline"
  }
}

# -----------------------------------------------------------------------------
# The firewall. Inbound: SSH from your address and nothing else. Outbound: open,
# because the server has to reach Red Hat's package servers and GitHub.
# -----------------------------------------------------------------------------
resource "aws_security_group" "stig_lab" {
  name        = "stig-lab"
  description = "SSH from my IP only; all outbound allowed"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH from my current public IP only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.myip.response_body)}/32"]
  }

  egress {
    description = "All outbound - needed for dnf package installs and git clone"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "stig-lab"
    Project = "rhel9-stig-pipeline"
  }
}

# -----------------------------------------------------------------------------
# The server itself.
# -----------------------------------------------------------------------------
resource "aws_instance" "stig_target" {
  ami                         = data.aws_ami.rhel9.id
  instance_type               = "t3.small"
  key_name                    = aws_key_pair.stig_lab.key_name
  vpc_security_group_ids      = [aws_security_group.stig_lab.id]
  associate_public_ip_address = true

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  tags = {
    Name    = "stig-target"
    Project = "rhel9-stig-pipeline"
  }
}
