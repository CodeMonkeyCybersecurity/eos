terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    consul = {
      source  = "hashicorp/consul"
      version = "~> 2.0"
    }
  }
}

# Variables
variable "environment" {
  description = "Environment name"
  type        = string
}

variable "component" {
  description = "Component name"
  type        = string
  default     = "vault"
}

variable "deployment_id" {
  description = "Unique deployment identifier"
  type        = string
}

variable "managed_by" {
  description = "Resource manager identifier"
  type        = string
  default     = "eos-infrastructure-compiler"
}

variable "vpc_id" {
  description = "VPC ID for deployment"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for deployment"
  type        = list(string)
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.small"
}

variable "cluster_size" {
  description = "Number of Vault nodes"
  type        = number
  default     = 3
}

variable "consul_cluster_tag" {
  description = "Tag to identify Consul cluster members"
  type        = string
  default     = "consul-cluster"
}

variable "enable_auto_unseal" {
  description = "Enable AWS KMS auto-unseal"
  type        = bool
  default     = true
}

# Data sources
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# KMS key for auto-unseal
resource "aws_kms_key" "vault" {
  count                   = var.enable_auto_unseal ? 1 : 0
  description             = "Vault auto-unseal key for ${var.environment}"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Name        = "${var.component}-${var.environment}-unseal"
    Environment = var.environment
    Component   = var.component
    ManagedBy   = var.managed_by
  }
}

resource "aws_kms_alias" "vault" {
  count         = var.enable_auto_unseal ? 1 : 0
  name          = "alias/${var.component}-${var.environment}-unseal"
  target_key_id = aws_kms_key.vault[0].key_id
}

# IAM role for Vault instances
resource "aws_iam_role" "vault" {
  name = "${var.component}-${var.environment}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.component}-${var.environment}-role"
    Environment = var.environment
    Component   = var.component
    ManagedBy   = var.managed_by
  }
}

# IAM policy for KMS access
resource "aws_iam_role_policy" "vault_kms" {
  count = var.enable_auto_unseal ? 1 : 0
  name  = "${var.component}-${var.environment}-kms"
  role  = aws_iam_role.vault.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.vault[0].arn
      }
    ]
  })
}

# IAM policy for EC2 discovery
resource "aws_iam_role_policy" "vault_discovery" {
  name = "${var.component}-${var.environment}-discovery"
  role = aws_iam_role.vault.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM instance profile
resource "aws_iam_instance_profile" "vault" {
  name = "${var.component}-${var.environment}-profile"
  role = aws_iam_role.vault.name
}

# Security Group
resource "aws_security_group" "vault" {
  name        = "${var.component}-${var.environment}-sg"
  description = "Security group for Vault cluster"
  vpc_id      = var.vpc_id

  # Vault API
  ingress {
    from_port   = 8200
    to_port     = 8200
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }

  # Vault Cluster
  ingress {
    from_port = 8201
    to_port   = 8201
    protocol  = "tcp"
    self      = true
  }

  # Consul
  ingress {
    from_port = 8300
    to_port   = 8302
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port = 8500
    to_port   = 8500
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port = 8600
    to_port   = 8600
    protocol  = "udp"
    self      = true
  }

  # SSH (restricted)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.component}-${var.environment}-sg"
    Environment = var.environment
    Component   = var.component
    ManagedBy   = var.managed_by
  }
}

# Launch Template
resource "aws_launch_template" "vault" {
  name_prefix   = "${var.component}-${var.environment}-"
  image_id      = data.aws_ami.ubuntu.id
  instance_type = var.instance_type

  iam_instance_profile {
    name = aws_iam_instance_profile.vault.name
  }

  vpc_security_group_ids = [aws_security_group.vault.id]

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    environment        = var.environment
    component          = var.component
    cluster_size       = var.cluster_size
    consul_cluster_tag = var.consul_cluster_tag
    kms_key_id        = var.enable_auto_unseal ? aws_kms_key.vault[0].id : ""
    aws_region        = data.aws_region.current.name
  }))

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size           = 20
      volume_type           = "gp3"
      iops                  = 3000
      delete_on_termination = true
      encrypted             = true
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name             = "${var.component}-${var.environment}-instance"
      Environment      = var.environment
      Component        = var.component
      ManagedBy        = var.managed_by
      "${var.consul_cluster_tag}" = "true"
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "vault" {
  name                = "${var.component}-${var.environment}-asg"
  vpc_zone_identifier = var.subnet_ids
  min_size            = var.cluster_size
  max_size            = var.cluster_size
  desired_capacity    = var.cluster_size
  health_check_type   = "EC2"
  health_check_grace_period = 300

  launch_template {
    id      = aws_launch_template.vault.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${var.component}-${var.environment}-asg"
    propagate_at_launch = true
  }

  tag {
    key                 = "Environment"
    value               = var.environment
    propagate_at_launch = true
  }

  tag {
    key                 = "Component"
    value               = var.component
    propagate_at_launch = true
  }

  tag {
    key                 = "ManagedBy"
    value               = var.managed_by
    propagate_at_launch = true
  }

  tag {
    key                 = var.consul_cluster_tag
    value               = "true"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Network Load Balancer for Vault
resource "aws_lb" "vault" {
  name               = "${var.component}-${var.environment}-nlb"
  internal           = true
  load_balancer_type = "network"
  subnets            = var.subnet_ids

  enable_deletion_protection = false
  enable_cross_zone_load_balancing = true

  tags = {
    Name        = "${var.component}-${var.environment}-nlb"
    Environment = var.environment
    Component   = var.component
    ManagedBy   = var.managed_by
  }
}

# Target Group for Vault API
resource "aws_lb_target_group" "vault_api" {
  name     = "${var.component}-${var.environment}-api"
  port     = 8200
  protocol = "TCP"
  vpc_id   = var.vpc_id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    port                = 8200
    protocol            = "TCP"
  }

  tags = {
    Name        = "${var.component}-${var.environment}-api"
    Environment = var.environment
    Component   = var.component
    ManagedBy   = var.managed_by
  }
}

# NLB Listener for Vault API
resource "aws_lb_listener" "vault_api" {
  load_balancer_arn = aws_lb.vault.arn
  port              = "8200"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.vault_api.arn
  }
}

# Attach ASG to Target Group
resource "aws_autoscaling_attachment" "vault_api" {
  autoscaling_group_name = aws_autoscaling_group.vault.id
  lb_target_group_arn    = aws_lb_target_group.vault_api.arn
}

# S3 bucket for Vault backups
resource "aws_s3_bucket" "vault_backups" {
  bucket = "${var.component}-${var.environment}-backups-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "${var.component}-${var.environment}-backups"
    Environment = var.environment
    Component   = var.component
    ManagedBy   = var.managed_by
  }
}

resource "aws_s3_bucket_versioning" "vault_backups" {
  bucket = aws_s3_bucket.vault_backups.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault_backups" {
  bucket = aws_s3_bucket.vault_backups.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "vault_backups" {
  bucket = aws_s3_bucket.vault_backups.id

  rule {
    id     = "expire-old-backups"
    status = "Enabled"

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# IAM policy for S3 backup access
resource "aws_iam_role_policy" "vault_backup" {
  name = "${var.component}-${var.environment}-backup"
  role = aws_iam_role.vault.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = aws_s3_bucket.vault_backups.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.vault_backups.arn}/*"
      }
    ]
  })
}

# Outputs
output "cluster_endpoint" {
  value = aws_lb.vault.dns_name
}

output "kms_key_id" {
  value = var.enable_auto_unseal ? aws_kms_key.vault[0].id : ""
}

output "backup_bucket" {
  value = aws_s3_bucket.vault_backups.id
}

output "security_group_id" {
  value = aws_security_group.vault.id
}

output "iam_role_arn" {
  value = aws_iam_role.vault.arn
}