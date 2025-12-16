terraform {
  required_version = ">= 1.3.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

############################
# Variables
############################

variable "region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "ap-south-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.20.0.0/16"
}

variable "private_subnet_cidr" {
  description = "CIDR block for the private subnet"
  type        = string
  default     = "10.20.1.0/24"
}

variable "allowed_ssh_cidr" {
  description = "CIDR allowed for SSH access (office / bastion IP range)"
  type        = string
  default     = "203.0.113.0/32"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

############################
# AMI – latest Amazon Linux 2023
############################

data "aws_ssm_parameter" "ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

############################
# VPC & Subnet (New)
############################

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name           = "secure-ec2-vpc"
    IT_OWNER_EMAIL = "anant.vaish@veolia.com"
  }
}

# Route table with no Internet Gateway attached → acts as private subnet
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name           = "secure-ec2-private-rt"
    IT_OWNER_EMAIL = "anant.vaish@veolia.com"
  }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.private_subnet_cidr
  map_public_ip_on_launch = false

  tags = {
    Name           = "secure-ec2-private-subnet"
    IT_OWNER_EMAIL = "anant.vaish@veolia.com"
  }
}

resource "aws_route_table_association" "private_assoc" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

############################
# Security Group
############################

resource "aws_security_group" "ec2_sg" {
  name        = "secure-ec2-sg"
  description = "Security group for secure EC2 (restricted SSH + minimal ingress)"
  vpc_id      = aws_vpc.main.id

  # SSH only from known CIDR (no 0.0.0.0/0)
  ingress {
    description = "SSH restricted"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  # HTTPS public (if workload needs it; remove if not required)
  ingress {
    description = "HTTPS public"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Outbound traffic (can be tightened later)
  egress {
    description = "Allow all egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name           = "secure-ec2-sg"
    IT_OWNER_EMAIL = "anant.vaish@veolia.com"
  }
}

############################
# IAM Role + Instance Profile
############################

data "aws_iam_policy_document" "ec2_trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ec2_role" {
  name               = "SecureEC2Role-TF"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json

  tags = {
    Name           = "SecureEC2Role-TF"
    IT_OWNER_EMAIL = "anant.vaish@veolia.com"
  }
}

resource "aws_iam_role_policy" "ec2_policy" {
  name = "SecureEC2Policy-TF"
  role = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DescribeOnly"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags",
          "ec2:DescribeVolumes"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "SecureEC2InstanceProfile-TF"
  role = aws_iam_role.ec2_role.name

  tags = {
    Name           = "SecureEC2InstanceProfile-TF"
    IT_OWNER_EMAIL = "anant.vaish@veolia.com"
  }
}

############################
# EC2 Instance (Secure Baseline)
############################

resource "aws_instance" "secure_ec2" {
  ami           = data.aws_ssm_parameter.ami.value
  instance_type = var.instance_type

  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]

  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  # No public IP – private subnet only
  associate_public_ip_address = false

  # Enforce IMDSv2
  metadata_options {
    http_tokens   = "required"   # IMDSv2 only
    http_endpoint = "enabled"
  }

  # Encrypted root EBS volume (uses account default KMS key)
  root_block_device {
    encrypted   = true
    volume_size = 20
    volume_type = "gp3"
  }

  tags = {
    Name           = "SecureEC2Instance"
    IT_OWNER_EMAIL = "anant.vaish@veolia.com"
  }
}

############################
# Outputs
############################

output "vpc_id" {
  description = "ID of the created VPC"
  value       = aws_vpc.main.id
}

output "private_subnet_id" {
  description = "ID of the created private subnet"
  value       = aws_subnet.private.id
}

output "security_group_id" {
  description = "ID of the security group for the secure EC2 instance"
  value       = aws_security_group.ec2_sg.id
}

output "iam_role_name" {
  description = "Name of the IAM role used by EC2"
  value       = aws_iam_role.ec2_role.name
}

output "instance_id" {
  description = "ID of the secure EC2 instance"
  value       = aws_instance.secure_ec2.id
}