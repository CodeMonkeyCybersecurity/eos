terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
    consul = {
      source  = "hashicorp/consul"
      version = "~> 2.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.0"
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
  default     = "hecate"
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

variable "domain" {
  description = "Base domain for services"
  type        = string
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
  default     = "t3.medium"
}

variable "instance_count" {
  description = "Number of instances"
  type        = number
  default     = 3
}

variable "enable_monitoring" {
  description = "Enable monitoring services"
  type        = bool
  default     = true
}

variable "enable_security" {
  description = "Enable security services"
  type        = bool
  default     = true
}

variable "services" {
  description = "Additional services to deploy"
  type        = list(string)
  default     = []
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

# Security Group
resource "aws_security_group" "hecate" {
  name        = "${var.component}-${var.environment}-sg"
  description = "Security group for Hecate reverse proxy"
  vpc_id      = var.vpc_id

  # HTTP
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
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

  # Vault
  ingress {
    from_port = 8200
    to_port   = 8201
    protocol  = "tcp"
    self      = true
  }

  # Nomad
  ingress {
    from_port = 4646
    to_port   = 4648
    protocol  = "tcp"
    self      = true
  }

  # Service ports
  dynamic "ingress" {
    for_each = var.services
    content {
      from_port = lookup(local.service_ports, ingress.value, 0)
      to_port   = lookup(local.service_ports, ingress.value, 0)
      protocol  = "tcp"
      self      = true
    }
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

# Service port mapping
locals {
  service_ports = {
    wazuh         = 55000
    grafana       = 3000
    prometheus    = 9090
    loki          = 3100
    elasticsearch = 9200
    kibana        = 5601
    mattermost    = 8065
    authentik     = 9000
    postgres      = 5432
    redis         = 6379
  }
}

# Launch Template
resource "aws_launch_template" "hecate" {
  name_prefix   = "${var.component}-${var.environment}-"
  image_id      = data.aws_ami.ubuntu.id
  instance_type = var.instance_type

  vpc_security_group_ids = [aws_security_group.hecate.id]

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    environment   = var.environment
    component     = var.component
    consul_addr   = var.consul_address
    vault_addr    = var.vault_address
    services      = join(",", var.services)
  }))

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size           = 50
      volume_type           = "gp3"
      iops                  = 3000
      throughput            = 125
      delete_on_termination = true
      encrypted             = true
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  monitoring {
    enabled = var.enable_monitoring
  }

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name        = "${var.component}-${var.environment}-instance"
      Environment = var.environment
      Component   = var.component
      ManagedBy   = var.managed_by
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "hecate" {
  name                = "${var.component}-${var.environment}-asg"
  vpc_zone_identifier = var.subnet_ids
  min_size            = var.instance_count
  max_size            = var.instance_count * 2
  desired_capacity    = var.instance_count
  health_check_type   = "ELB"
  health_check_grace_period = 300

  launch_template {
    id      = aws_launch_template.hecate.id
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

  lifecycle {
    create_before_destroy = true
  }
}

# Application Load Balancer
resource "aws_lb" "hecate" {
  name               = "${var.component}-${var.environment}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.hecate.id]
  subnets            = var.subnet_ids

  enable_deletion_protection = false
  enable_http2              = true
  enable_cross_zone_load_balancing = true

  tags = {
    Name        = "${var.component}-${var.environment}-alb"
    Environment = var.environment
    Component   = var.component
    ManagedBy   = var.managed_by
  }
}

# Target Group
resource "aws_lb_target_group" "hecate" {
  name     = "${var.component}-${var.environment}-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = "/health"
    matcher             = "200"
  }

  stickiness {
    type            = "lb_cookie"
    cookie_duration = 86400
    enabled         = true
  }

  tags = {
    Name        = "${var.component}-${var.environment}-tg"
    Environment = var.environment
    Component   = var.component
    ManagedBy   = var.managed_by
  }
}

# ALB Listeners
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.hecate.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.hecate.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.hecate.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.hecate.arn
  }
}

# Attach ASG to Target Group
resource "aws_autoscaling_attachment" "hecate" {
  autoscaling_group_name = aws_autoscaling_group.hecate.id
  lb_target_group_arn    = aws_lb_target_group.hecate.arn
}

# ACM Certificate
resource "aws_acm_certificate" "hecate" {
  domain_name       = "*.${var.domain}"
  validation_method = "DNS"

  subject_alternative_names = [
    var.domain,
    "*.${var.domain}"
  ]

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name        = "${var.component}-${var.environment}-cert"
    Environment = var.environment
    Component   = var.component
    ManagedBy   = var.managed_by
  }
}

# Route53 Zone
data "aws_route53_zone" "main" {
  name = var.domain
}

# Certificate Validation
resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.hecate.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.main.zone_id
}

resource "aws_acm_certificate_validation" "hecate" {
  certificate_arn         = aws_acm_certificate.hecate.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# DNS Records
resource "aws_route53_record" "hecate" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = var.domain
  type    = "A"

  alias {
    name                   = aws_lb.hecate.dns_name
    zone_id                = aws_lb.hecate.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "wildcard" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "*.${var.domain}"
  type    = "A"

  alias {
    name                   = aws_lb.hecate.dns_name
    zone_id                = aws_lb.hecate.zone_id
    evaluate_target_health = true
  }
}

# Cloudflare DNS (if using Cloudflare)
resource "cloudflare_record" "hecate" {
  count   = var.use_cloudflare ? 1 : 0
  zone_id = var.cloudflare_zone_id
  name    = "@"
  value   = aws_lb.hecate.dns_name
  type    = "CNAME"
  ttl     = 1
  proxied = true
}

resource "cloudflare_record" "wildcard" {
  count   = var.use_cloudflare ? 1 : 0
  zone_id = var.cloudflare_zone_id
  name    = "*"
  value   = aws_lb.hecate.dns_name
  type    = "CNAME"
  ttl     = 1
  proxied = true
}

# Outputs
output "alb_dns_name" {
  value = aws_lb.hecate.dns_name
}

output "alb_zone_id" {
  value = aws_lb.hecate.zone_id
}

output "security_group_id" {
  value = aws_security_group.hecate.id
}

output "asg_name" {
  value = aws_autoscaling_group.hecate.name
}

output "target_group_arn" {
  value = aws_lb_target_group.hecate.arn
}