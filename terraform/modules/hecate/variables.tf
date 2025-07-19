variable "consul_address" {
  description = "Consul cluster address"
  type        = string
  default     = ""
}

variable "vault_address" {
  description = "Vault cluster address"
  type        = string
  default     = ""
}

variable "boundary_address" {
  description = "Boundary controller address"
  type        = string
  default     = ""
}

variable "use_cloudflare" {
  description = "Use Cloudflare for DNS"
  type        = bool
  default     = false
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID"
  type        = string
  default     = ""
}

variable "enable_waf" {
  description = "Enable WAF protection"
  type        = bool
  default     = true
}

variable "waf_mode" {
  description = "WAF mode (detect or block)"
  type        = string
  default     = "detect"
}

variable "backup_enabled" {
  description = "Enable automated backups"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Backup retention in days"
  type        = number
  default     = 30
}

variable "monitoring_endpoints" {
  description = "Monitoring endpoints to configure"
  type = map(object({
    url      = string
    interval = string
    timeout  = string
  }))
  default = {}
}

variable "ssl_policy" {
  description = "SSL policy for load balancer"
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

variable "enable_access_logs" {
  description = "Enable ALB access logs"
  type        = bool
  default     = true
}

variable "access_logs_bucket" {
  description = "S3 bucket for ALB access logs"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Additional tags for resources"
  type        = map(string)
  default     = {}
}