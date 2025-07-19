variable "hetzner_token" {
  description = "Hetzner Cloud API token"
  type        = string
  sensitive   = true
}

variable "dns_zone" {
  description = "DNS zone name"
  type        = string
}

variable "ingress_ip" {
  description = "Ingress IP address for DNS records"
  type        = string
}

variable "enable_monitoring" {
  description = "Enable monitoring for deployed resources"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Number of days to retain backups"
  type        = number
  default     = 30
}