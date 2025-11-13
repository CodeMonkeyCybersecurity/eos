# Wazuh MSSP Platform - Complete Implementation

*Last Updated: 2025-01-14*

This implementation provides all the files and configurations needed for the Wazuh MSSP platform. Each file is ready to be placed in the eos repository under `modules/wazuh-mssp/`.

## Directory Structure

```
modules/wazuh-mssp/
├── README.md
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── versions.tf
│   ├── modules/
│   │   ├── kvm-infrastructure/
│   │   ├── nomad-cluster/
│   │   ├── temporal-cluster/
│   │   ├── nats-cluster/
│   │   ├── ccs-environment/
│   │   └── customer-environment/
│   └── environments/
│       ├── dev/
│       ├── staging/
│       └── production/
├── nomad/
│   ├── jobs/
│   ├── packs/
│   └── policies/
├── /
│   ├── states/
│   ├── /
│   └── orchestration/
├── temporal/
│   ├── workflows/
│   ├── activities/
│   ├── workers/
│   └── cmd/
├── benthos/
│   ├── configs/
│   └── templates/
├── scripts/
│   ├── eos-wazuh-ccs.sh
│   └── utils/
├── docker/
│   └── docker-compose.yml
└── docs/
    ├── architecture.md
    ├── deployment.md
    └── operations.md
```

## File Contents

### 1. README.md

```markdown
# Wazuh MSSP Platform

A multi-tenant Wazuh deployment platform for Managed Security Service Providers (MSSPs) using HashiCorp Nomad, Temporal, NATS, and Benthos.

## Features

- Multi-tenant Wazuh deployments with complete isolation
- Cross-Cluster Search (CCS) for centralized SOC operations
- Self-service customer onboarding through Authentik SSO
- Automated provisioning with Temporal workflows
- Event-driven architecture with NATS and Benthos
- Infrastructure as Code with Terraform and 
- Support for multiple customer tiers (starter/pro/enterprise)

## Quick Start

```bash
# Initialize the platform
eos create wazuh-ccs --init

# Add a customer
eos create wazuh-ccs --add-customer customer-config.json

# Scale a customer
eos create wazuh-ccs --scale-customer cust_12345 enterprise

# Remove a customer
eos create wazuh-ccs --remove-customer cust_12345
```

## Architecture

See [docs/architecture.md](docs/architecture.md) for detailed architecture documentation.

## Requirements

- Ubuntu 22.04/24.04 hosts with KVM/libvirt
- Nomad 1.7+ cluster
- Temporal 1.22+ server
- NATS 2.10+ with JetStream
-  3006+
- Terraform 1.5+
```

### 2. terraform/main.tf

```hcl
# modules/wazuh-mssp/terraform/main.tf
# Main Terraform configuration for Wazuh MSSP Platform

terraform {
  required_version = ">= 1.5.0"
  
  backend "s3" {
    # Backend configuration will be provided during init
  }
}

# Local variables
locals {
  platform_name = var.platform_name
  environment   = var.environment
  
  common_tags = merge(var.tags, {
    Platform    = local.platform_name
    Environment = local.environment
    ManagedBy   = "terraform"
  })
}

# KVM Infrastructure Module
module "kvm_infrastructure" {
  source = "./modules/kvm-infrastructure"
  
  hypervisor_hosts = var.hypervisor_hosts
  network_config   = var.network_config
  storage_pools    = var.storage_pools
  
  tags = local.common_tags
}

# Nomad Cluster Module
module "nomad_cluster" {
  source = "./modules/nomad-cluster"
  
  cluster_name         = "${local.platform_name}-nomad"
  datacenter          = var.datacenter
  server_count        = var.nomad_server_count
  client_count        = var.nomad_client_count
  
  server_resources = var.nomad_server_resources
  client_resources = var.nomad_client_resources
  
  network_id = module.kvm_infrastructure.platform_network_id
  
  enable_consul  = true
  enable_vault   = true
  
  tags = local.common_tags
}

# Temporal Cluster Module
module "temporal_cluster" {
  source = "./modules/temporal-cluster"
  
  cluster_name = "${local.platform_name}-temporal"
  namespace    = "default"
  
  server_count = var.temporal_server_count
  server_resources = var.temporal_server_resources
  
  database_resources = var.temporal_database_resources
  
  network_id = module.kvm_infrastructure.platform_network_id
  
  nomad_namespace = "temporal"
  consul_service_name = "temporal"
  
  tags = local.common_tags
}

# NATS Cluster Module
module "nats_cluster" {
  source = "./modules/nats-cluster"
  
  cluster_name = "${local.platform_name}-nats"
  server_count = var.nats_server_count
  
  server_resources = var.nats_server_resources
  
  enable_jetstream = true
  jetstream_config = var.nats_jetstream_config
  
  network_id = module.kvm_infrastructure.platform_network_id
  
  nomad_namespace = "platform"
  
  tags = local.common_tags
}

# CCS Environment Module
module "ccs_environment" {
  source = "./modules/ccs-environment"
  
  environment_name = "${local.platform_name}-ccs"
  
  indexer_resources  = var.ccs_indexer_resources
  dashboard_resources = var.ccs_dashboard_resources
  
  network_id = module.kvm_infrastructure.platform_network_id
  
  wazuh_version = var.wazuh_version
  
  tags = local.common_tags
}

# Authentik Configuration
resource "terraform_data" "authentik_config" {
  provisioner "local-exec" {
    command = "${path.module}/scripts/configure-authentik.sh"
    
    environment = {
      AUTHENTIK_URL   = var.authentik_url
      AUTHENTIK_TOKEN = var.authentik_token
      PLATFORM_URL    = "https://${var.platform_domain}"
    }
  }
  
  depends_on = [
    module.nomad_cluster,
    module.temporal_cluster
  ]
}
```

### 3. terraform/variables.tf

```hcl
# modules/wazuh-mssp/terraform/variables.tf
# Input variables for Wazuh MSSP Platform

variable "platform_name" {
  description = "Name of the MSSP platform"
  type        = string
  default     = "wazuh-mssp"
}

variable "environment" {
  description = "Environment name (dev, staging, production)"
  type        = string
  
  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be dev, staging, or production."
  }
}

variable "datacenter" {
  description = "Datacenter name for Nomad"
  type        = string
  default     = "dc1"
}

variable "hypervisor_hosts" {
  description = "List of hypervisor hosts for KVM"
  type = list(object({
    hostname   = string
    ip_address = string
    ssh_user   = string
    ssh_key    = string
  }))
}

variable "network_config" {
  description = "Network configuration for the platform"
  type = object({
    platform_cidr = string
    customer_cidr = string
    vlan_range    = object({
      start = number
      end   = number
    })
  })
  
  default = {
    platform_cidr = "10.0.0.0/16"
    customer_cidr = "10.100.0.0/16"
    vlan_range = {
      start = 100
      end   = 999
    }
  }
}

variable "storage_pools" {
  description = "Storage pool configuration"
  type = map(object({
    path = string
    size = string
  }))
  
  default = {
    default = {
      path = "/var/lib/libvirt/images"
      size = "1TB"
    }
    fast = {
      path = "/mnt/ssd/libvirt/images"
      size = "500GB"
    }
  }
}

variable "nomad_server_count" {
  description = "Number of Nomad servers"
  type        = number
  default     = 3
}

variable "nomad_client_count" {
  description = "Number of Nomad clients"
  type        = number
  default     = 5
}

variable "nomad_server_resources" {
  description = "Resource allocation for Nomad servers"
  type = object({
    vcpus  = number
    memory = string
    disk   = string
  })
  
  default = {
    vcpus  = 2
    memory = "4096"
    disk   = "50G"
  }
}

variable "nomad_client_resources" {
  description = "Resource allocation for Nomad clients"
  type = object({
    vcpus  = number
    memory = string
    disk   = string
  })
  
  default = {
    vcpus  = 8
    memory = "16384"
    disk   = "200G"
  }
}

variable "temporal_server_count" {
  description = "Number of Temporal servers"
  type        = number
  default     = 1
}

variable "temporal_server_resources" {
  description = "Resource allocation for Temporal servers"
  type = object({
    vcpus  = number
    memory = string
    disk   = string
  })
  
  default = {
    vcpus  = 4
    memory = "8192"
    disk   = "100G"
  }
}

variable "temporal_database_resources" {
  description = "Resource allocation for Temporal database"
  type = object({
    vcpus  = number
    memory = string
    disk   = string
  })
  
  default = {
    vcpus  = 2
    memory = "4096"
    disk   = "50G"
  }
}

variable "nats_server_count" {
  description = "Number of NATS servers"
  type        = number
  default     = 3
}

variable "nats_server_resources" {
  description = "Resource allocation for NATS servers"
  type = object({
    vcpus  = number
    memory = string
    disk   = string
  })
  
  default = {
    vcpus  = 2
    memory = "4096"
    disk   = "100G"
  }
}

variable "nats_jetstream_config" {
  description = "NATS JetStream configuration"
  type = object({
    max_memory = string
    max_file   = string
  })
  
  default = {
    max_memory = "4GB"
    max_file   = "100GB"
  }
}

variable "ccs_indexer_resources" {
  description = "Resource allocation for CCS indexer"
  type = object({
    vcpus  = number
    memory = string
    disk   = string
  })
  
  default = {
    vcpus  = 4
    memory = "8192"
    disk   = "200G"
  }
}

variable "ccs_dashboard_resources" {
  description = "Resource allocation for CCS dashboard"
  type = object({
    vcpus  = number
    memory = string
    disk   = string
  })
  
  default = {
    vcpus  = 2
    memory = "4096"
    disk   = "50G"
  }
}

variable "wazuh_version" {
  description = "Wazuh version to deploy"
  type        = string
  default     = "4.8.2"
}

variable "platform_domain" {
  description = "Domain name for the platform"
  type        = string
}

variable "authentik_url" {
  description = "Authentik URL"
  type        = string
}

variable "authentik_token" {
  description = "Authentik API token"
  type        = string
  sensitive   = true
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
```

### 4. terraform/modules/kvm-infrastructure/main.tf

```hcl
# modules/wazuh-mssp/terraform/modules/kvm-infrastructure/main.tf
# KVM/libvirt infrastructure module

terraform {
  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.7.0"
    }
  }
}

# Configure libvirt providers for each hypervisor
locals {
  hypervisors = { for h in var.hypervisor_hosts : h.hostname => h }
}

# Platform network (shared across all hypervisors)
resource "libvirt_network" "platform" {
  for_each = local.hypervisors
  
  name      = "wazuh-platform"
  mode      = "bridge"
  bridge    = "br-platform"
  autostart = true
  
  addresses = [var.network_config.platform_cidr]
  
  dhcp {
    enabled = false
  }
  
  dns {
    enabled = true
    local_only = false
  }
  
  xml {
    xslt = file("${path.module}/templates/network-platform.xsl")
  }
}

# Storage pools
resource "libvirt_pool" "storage" {
  for_each = var.storage_pools
  
  name = each.key
  type = "dir"
  path = each.value.path
}

# Base images
resource "libvirt_volume" "ubuntu_base" {
  for_each = local.hypervisors
  
  name   = "ubuntu-22.04-base.qcow2"
  pool   = "default"
  source = "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
  format = "qcow2"
}

# Cloud-init base configuration
resource "libvirt_cloudinit_disk" "base_config" {
  name = "base-config.iso"
  pool = "default"
  
  user_data = templatefile("${path.module}/templates/cloud-init-base.yaml", {
    ssh_authorized_keys = var.ssh_authorized_keys
    _master         = var._master_ip
  })
  
  network_config = templatefile("${path.module}/templates/network-config.yaml", {
    gateway = cidrhost(var.network_config.platform_cidr, 1)
  })
}

# Customer network template
resource "libvirt_network" "customer_template" {
  name      = "customer-template"
  mode      = "none"
  autostart = false
  
  xml {
    xslt = file("${path.module}/templates/network-customer.xsl")
  }
}

# Output useful information
output "platform_network_id" {
  value = values(libvirt_network.platform)[0].id
}

output "storage_pool_ids" {
  value = { for k, v in libvirt_pool.storage : k => v.id }
}

output "ubuntu_base_image_id" {
  value = values(libvirt_volume.ubuntu_base)[0].id
}

output "hypervisor_connections" {
  value = { for k, v in local.hypervisors : k => "qemu+ssh://${v.ssh_user}@${v.ip_address}/system" }
}
```

### 5. terraform/modules/nomad-cluster/main.tf

```hcl
# modules/wazuh-mssp/terraform/modules/nomad-cluster/main.tf
# Nomad cluster deployment on KVM

terraform {
  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.7.0"
    }
  }
}

# Nomad server instances
resource "libvirt_domain" "nomad_server" {
  count = var.server_count
  
  name   = "${var.cluster_name}-server-${count.index + 1}"
  memory = var.server_resources.memory
  vcpu   = var.server_resources.vcpus
  
  cpu {
    mode = "host-passthrough"
  }
  
  disk {
    volume_id = libvirt_volume.nomad_server[count.index].id
  }
  
  network_interface {
    network_id     = var.network_id
    wait_for_lease = true
  }
  
  cloudinit = libvirt_cloudinit_disk.nomad_server[count.index].id
  
  console {
    type        = "pty"
    target_port = "0"
    target_type = "serial"
  }
  
  console {
    type        = "pty"
    target_type = "virtio"
    target_port = "1"
  }
  
  graphics {
    type        = "spice"
    listen_type = "address"
    autoport    = true
  }
}

# Nomad server volumes
resource "libvirt_volume" "nomad_server" {
  count = var.server_count
  
  name           = "${var.cluster_name}-server-${count.index + 1}.qcow2"
  pool           = "default"
  base_volume_id = var.base_image_id
  size           = var.server_resources.disk
  format         = "qcow2"
}

# Nomad server cloud-init
resource "libvirt_cloudinit_disk" "nomad_server" {
  count = var.server_count
  
  name = "${var.cluster_name}-server-${count.index + 1}-init.iso"
  pool = "default"
  
  user_data = templatefile("${path.module}/templates/nomad-server-init.yaml", {
    hostname       = "${var.cluster_name}-server-${count.index + 1}"
    server_count   = var.server_count
    datacenter     = var.datacenter
    consul_encrypt = random_id.consul_encrypt.b64_std
    node_role      = "server"
    server_index   = count.index
  })
  
  network_config = templatefile("${path.module}/templates/network-config.yaml", {
    address = cidrhost(var.platform_cidr, 10 + count.index)
    gateway = cidrhost(var.platform_cidr, 1)
  })
}

# Nomad client instances
resource "libvirt_domain" "nomad_client" {
  count = var.client_count
  
  name   = "${var.cluster_name}-client-${count.index + 1}"
  memory = var.client_resources.memory
  vcpu   = var.client_resources.vcpus
  
  cpu {
    mode = "host-passthrough"
  }
  
  # Enable nested virtualization for running containers
  xml {
    xslt = file("${path.module}/templates/enable-nested-virt.xsl")
  }
  
  disk {
    volume_id = libvirt_volume.nomad_client[count.index].id
  }
  
  network_interface {
    network_id     = var.network_id
    wait_for_lease = true
  }
  
  cloudinit = libvirt_cloudinit_disk.nomad_client[count.index].id
  
  console {
    type        = "pty"
    target_port = "0"
    target_type = "serial"
  }
}

# Nomad client volumes
resource "libvirt_volume" "nomad_client" {
  count = var.client_count
  
  name           = "${var.cluster_name}-client-${count.index + 1}.qcow2"
  pool           = "default"
  base_volume_id = var.base_image_id
  size           = var.client_resources.disk
  format         = "qcow2"
}

# Nomad client cloud-init
resource "libvirt_cloudinit_disk" "nomad_client" {
  count = var.client_count
  
  name = "${var.cluster_name}-client-${count.index + 1}-init.iso"
  pool = "default"
  
  user_data = templatefile("${path.module}/templates/nomad-client-init.yaml", {
    hostname       = "${var.cluster_name}-client-${count.index + 1}"
    servers        = [for i in range(var.server_count) : cidrhost(var.platform_cidr, 10 + i)]
    datacenter     = var.datacenter
    consul_encrypt = random_id.consul_encrypt.b64_std
    node_role      = "client"
    node_class     = "general"
  })
  
  network_config = templatefile("${path.module}/templates/network-config.yaml", {
    address = cidrhost(var.platform_cidr, 20 + count.index)
    gateway = cidrhost(var.platform_cidr, 1)
  })
}

# Consul encryption key
resource "random_id" "consul_encrypt" {
  byte_length = 16
}

# Bootstrap ACLs after cluster is up
resource "null_resource" "bootstrap_acls" {
  depends_on = [
    libvirt_domain.nomad_server,
    libvirt_domain.nomad_client
  ]
  
  provisioner "local-exec" {
    command = "${path.module}/scripts/bootstrap-nomad-acls.sh"
    
    environment = {
      NOMAD_ADDR = "http://${libvirt_domain.nomad_server[0].network_interface[0].addresses[0]}:4646"
    }
  }
}

# Outputs
output "nomad_server_ips" {
  value = [for s in libvirt_domain.nomad_server : s.network_interface[0].addresses[0]]
}

output "nomad_client_ips" {
  value = [for c in libvirt_domain.nomad_client : c.network_interface[0].addresses[0]]
}

output "consul_encrypt_key" {
  value     = random_id.consul_encrypt.b64_std
  sensitive = true
}

output "platform_namespace" {
  value = "platform"
}

output "temporal_namespace" {
  value = "temporal"
}
```

### 6. nomad/jobs/api-service.nomad

```hcl
# modules/wazuh-mssp/nomad/jobs/api-service.nomad
# API service for the Wazuh MSSP platform

job "wazuh-api" {
  datacenters = ["dc1"]
  type        = "service"
  namespace   = "platform"
  
  update {
    max_parallel      = 2
    health_check      = "checks"
    min_healthy_time  = "30s"
    healthy_deadline  = "5m"
    progress_deadline = "10m"
    auto_revert       = true
    auto_promote      = true
    canary            = 2
  }
  
  group "api" {
    count = 3
    
    constraint {
      attribute = "${node.class}"
      operator  = "="
      value     = "general"
    }
    
    restart {
      attempts = 3
      interval = "5m"
      delay    = "15s"
      mode     = "delay"
    }
    
    network {
      mode = "bridge"
      
      port "http" {
        to = 8000
      }
      
      port "metrics" {
        to = 9090
      }
    }
    
    service {
      name = "wazuh-api"
      port = "http"
      
      tags = [
        "traefik.enable=true",
        "traefik.http.routers.api.rule=Host(`api.${NOMAD_META_platform_domain}`)",
        "traefik.http.routers.api.tls=true",
        "traefik.http.routers.api.tls.certresolver=letsencrypt",
        "traefik.http.routers.api.middlewares=auth@file",
      ]
      
      connect {
        sidecar_service {
          proxy {
            upstreams {
              destination_name = "temporal-frontend"
              local_bind_port  = 7233
            }
            
            upstreams {
              destination_name = "nats"
              local_bind_port  = 4222
            }
            
            upstreams {
              destination_name = "postgres"
              local_bind_port  = 5432
            }
            
            upstreams {
              destination_name = "vault"
              local_bind_port  = 8200
            }
          }
        }
      }
      
      check {
        name     = "api-health"
        type     = "http"
        path     = "/health"
        interval = "10s"
        timeout  = "2s"
        
        check_restart {
          limit = 3
          grace = "30s"
        }
      }
      
      check {
        name     = "api-ready"
        type     = "http"
        path     = "/ready"
        interval = "10s"
        timeout  = "2s"
      }
    }
    
    service {
      name = "wazuh-api-metrics"
      port = "metrics"
      
      tags = ["prometheus"]
      
      meta {
        prometheus_path = "/metrics"
      }
    }
    
    task "api" {
      driver = "docker"
      
      config {
        image = "${NOMAD_META_docker_registry}/wazuh-mssp/api:${NOMAD_META_api_version}"
        ports = ["http", "metrics"]
        
        volumes = [
          "local/config.yaml:/app/config.yaml:ro",
        ]
      }
      
      vault {
        policies = ["wazuh-api"]
        
        change_mode   = "signal"
        change_signal = "SIGUSR1"
      }
      
      template {
        data = <<EOF
{{- with secret "database/creds/wazuh-api" }}
DATABASE_URL="postgresql://{{ .Data.username }}:{{ .Data.password }}@localhost:5432/wazuh_mssp"
{{- end }}

{{- with secret "kv/data/api/config" }}
JWT_SECRET="{{ .Data.data.jwt_secret }}"
STRIPE_API_KEY="{{ .Data.data.stripe_api_key }}"
STRIPE_WEBHOOK_SECRET="{{ .Data.data.stripe_webhook_secret }}"
AUTHENTIK_URL="{{ .Data.data.authentik_url }}"
AUTHENTIK_TOKEN="{{ .Data.data.authentik_token }}"
{{- end }}

TEMPORAL_ADDRESS="localhost:7233"
TEMPORAL_NAMESPACE="default"
NATS_URL="nats://localhost:4222"
VAULT_ADDR="http://localhost:8200"
LOG_LEVEL="info"
ENVIRONMENT="{{ env "NOMAD_META_environment" }}"
EOF
        
        destination = "secrets/.env"
        env         = true
      }
      
      template {
        data = <<EOF
server:
  host: 0.0.0.0
  port: 8000
  cors:
    enabled: true
    origins:
      - https://{{ env "NOMAD_META_platform_domain" }}
      - https://*.{{ env "NOMAD_META_platform_domain" }}

auth:
  jwt:
    issuer: "wazuh-mssp"
    audience: "wazuh-api"
    expiry: "24h"
  
  authentik:
    enabled: true
    client_id: "{{ env "AUTHENTIK_CLIENT_ID" }}"

database:
  max_connections: 20
  max_idle: 5
  max_lifetime: "1h"

temporal:
  task_queues:
    - provisioning
    - operations
    - billing
    - monitoring

nats:
  subjects:
    webhooks: "webhooks.>"
    customer_events: "customer.*.events"
    platform_events: "platform.events"

ratelimit:
  enabled: true
  requests_per_minute: 60
  burst: 10

metrics:
  port: 9090
  path: /metrics
EOF
        
        destination = "local/config.yaml"
      }
      
      resources {
        cpu    = 1000
        memory = 1024
      }
      
      scaling {
        enabled = true
        min     = 2
        max     = 10
        
        policy {
          check "cpu" {
            source = "nomad-apm"
            query  = "avg_cpu"
            
            strategy "target-value" {
              target = 70
            }
          }
          
          check "response_time" {
            source = "prometheus"
            query  = "http_request_duration_seconds{job='wazuh-api',quantile='0.95'}"
            
            strategy "target-value" {
              target = 0.5
            }
          }
        }
      }
    }
  }
}
```

### 7. nomad/jobs/temporal-worker.nomad

```hcl
# modules/wazuh-mssp/nomad/jobs/temporal-worker.nomad
# Temporal workers for different task queues

job "temporal-workers" {
  datacenters = ["dc1"]
  type        = "service"
  namespace   = "temporal"
  
  update {
    max_parallel      = 1
    health_check      = "checks"
    min_healthy_time  = "30s"
    healthy_deadline  = "5m"
    auto_revert       = true
    auto_promote      = true
  }
  
  # Provisioning workers
  group "provisioning" {
    count = 3
    
    restart {
      attempts = 3
      interval = "5m"
      delay    = "15s"
      mode     = "delay"
    }
    
    network {
      mode = "bridge"
      
      port "metrics" {
        to = 9090
      }
    }
    
    service {
      name = "temporal-worker-provisioning"
      port = "metrics"
      
      tags = ["temporal", "worker", "provisioning"]
      
      connect {
        sidecar_service {
          proxy {
            upstreams {
              destination_name = "temporal-frontend"
              local_bind_port  = 7233
            }
            
            upstreams {
              destination_name = "nomad"
              local_bind_port  = 4646
            }
            
            upstreams {
              destination_name = "consul"
              local_bind_port  = 8161
            }
            
            upstreams {
              destination_name = "vault"
              local_bind_port  = 8200
            }
            
            upstreams {
              destination_name = "-api"
              local_bind_port  = 8080
            }
          }
        }
      }
      
      check {
        name     = "worker-health"
        type     = "http"
        path     = "/health"
        port     = "metrics"
        interval = "10s"
        timeout  = "2s"
      }
    }
    
    task "worker" {
      driver = "docker"
      
      config {
        image = "${NOMAD_META_docker_registry}/wazuh-mssp/temporal-worker:${NOMAD_META_worker_version}"
        ports = ["metrics"]
        
        command = "/app/worker"
        args    = ["--task-queue", "provisioning"]
      }
      
      vault {
        policies = ["temporal-worker", "terraform-executor"]
        
        change_mode = "restart"
      }
      
      template {
        data = <<EOF
TEMPORAL_ADDRESS=localhost:7233
TEMPORAL_NAMESPACE=default
TASK_QUEUE=provisioning
WORKER_ID={{ env "NOMAD_ALLOC_ID" }}
WORKER_BUILD_ID={{ env "NOMAD_META_worker_version" }}

{{- with secret "kv/data/temporal/worker" }}
TERRAFORM_CLOUD_TOKEN="{{ .Data.data.terraform_cloud_token }}"
NOMAD_TOKEN="{{ .Data.data.nomad_token }}"
CONSUL_TOKEN="{{ .Data.data.consul_token }}"
VAULT_TOKEN="{{ .Data.data.vault_token }}"
_API_URL="{{ .Data.data._api_url }}"
_API_TOKEN="{{ .Data.data._api_token }}"
{{- end }}

{{- with secret "kv/data/aws/config" }}
AWS_ACCESS_KEY_ID="{{ .Data.data.access_key_id }}"
AWS_SECRET_ACCESS_KEY="{{ .Data.data.secret_access_key }}"
AWS_REGION="{{ .Data.data.region }}"
TERRAFORM_STATE_BUCKET="{{ .Data.data.terraform_state_bucket }}"
{{- end }}

LOG_LEVEL=info
METRICS_PORT=9090
OTLP_ENDPOINT=http://otel-collector.service.consul:4317
EOF
        
        destination = "secrets/.env"
        env         = true
      }
      
      template {
        data = <<EOF
# Terraform wrapper script
#!/bin/bash
set -euo pipefail

export TF_IN_AUTOMATION=true
export TF_INPUT=false
export TF_CLI_ARGS="-no-color"

# Initialize working directory
mkdir -p /tmp/terraform/${CUSTOMER_ID}
cd /tmp/terraform/${CUSTOMER_ID}

# Download module
terraform init \
  -backend-config="bucket=${TERRAFORM_STATE_BUCKET}" \
  -backend-config="key=customers/${CUSTOMER_ID}/terraform.tfstate" \
  -backend-config="region=${AWS_REGION}"

# Apply with timeout
timeout 1800 terraform apply -auto-approve -var-file=/tmp/terraform.tfvars
EOF
        
        destination = "local/terraform-wrapper.sh"
        perms       = "755"
      }
      
      resources {
        cpu    = 2000
        memory = 2048
      }
    }
  }
  
  # Operations workers
  group "operations" {
    count = 2
    
    network {
      mode = "bridge"
      
      port "metrics" {
        to = 9090
      }
    }
    
    service {
      name = "temporal-worker-operations"
      port = "metrics"
      
      tags = ["temporal", "worker", "operations"]
      
      connect {
        sidecar_service {
          proxy {
            upstreams {
              destination_name = "temporal-frontend"
              local_bind_port  = 7233
            }
            
            upstreams {
              destination_name = "nomad"
              local_bind_port  = 4646
            }
            
            upstreams {
              destination_name = "vault"
              local_bind_port  = 8200
            }
            
            upstreams {
              destination_name = "postgres"
              local_bind_port  = 5432
            }
          }
        }
      }
    }
    
    task "worker" {
      driver = "docker"
      
      config {
        image = "${NOMAD_META_docker_registry}/wazuh-mssp/temporal-worker:${NOMAD_META_worker_version}"
        ports = ["metrics"]
        
        command = "/app/worker"
        args    = ["--task-queue", "operations"]
      }
      
      vault {
        policies = ["temporal-worker"]
      }
      
      template {
        data = <<EOF
TEMPORAL_ADDRESS=localhost:7233
TEMPORAL_NAMESPACE=default
TASK_QUEUE=operations
WORKER_ID={{ env "NOMAD_ALLOC_ID" }}

{{- with secret "kv/data/temporal/worker" }}
NOMAD_TOKEN="{{ .Data.data.nomad_token }}"
VAULT_TOKEN="{{ .Data.data.vault_token }}"
{{- end }}

{{- with secret "database/creds/temporal-worker" }}
DATABASE_URL="postgresql://{{ .Data.username }}:{{ .Data.password }}@localhost:5432/wazuh_mssp"
{{- end }}

LOG_LEVEL=info
METRICS_PORT=9090
EOF
        
        destination = "secrets/.env"
        env         = true
      }
      
      resources {
        cpu    = 1000
        memory = 1024
      }
    }
  }
  
  # Billing workers
  group "billing" {
    count = 2
    
    network {
      mode = "bridge"
      
      port "metrics" {
        to = 9090
      }
    }
    
    service {
      name = "temporal-worker-billing"
      port = "metrics"
      
      tags = ["temporal", "worker", "billing"]
      
      connect {
        sidecar_service {
          proxy {
            upstreams {
              destination_name = "temporal-frontend"
              local_bind_port  = 7233
            }
            
            upstreams {
              destination_name = "postgres"
              local_bind_port  = 5432
            }
            
            upstreams {
              destination_name = "stripe-api"
              local_bind_port  = 443
            }
          }
        }
      }
    }
    
    task "worker" {
      driver = "docker"
      
      config {
        image = "${NOMAD_META_docker_registry}/wazuh-mssp/temporal-worker:${NOMAD_META_worker_version}"
        ports = ["metrics"]
        
        command = "/app/worker"
        args    = ["--task-queue", "billing"]
      }
      
      vault {
        policies = ["temporal-worker", "billing"]
      }
      
      template {
        data = <<EOF
TEMPORAL_ADDRESS=localhost:7233
TEMPORAL_NAMESPACE=default
TASK_QUEUE=billing
WORKER_ID={{ env "NOMAD_ALLOC_ID" }}

{{- with secret "kv/data/stripe/config" }}
STRIPE_API_KEY="{{ .Data.data.api_key }}"
STRIPE_WEBHOOK_SECRET="{{ .Data.data.webhook_secret }}"
{{- end }}

{{- with secret "database/creds/billing" }}
DATABASE_URL="postgresql://{{ .Data.username }}:{{ .Data.password }}@localhost:5432/wazuh_mssp_billing"
{{- end }}

LOG_LEVEL=info
METRICS_PORT=9090
EOF
        
        destination = "secrets/.env"
        env         = true
      }
      
      resources {
        cpu    = 500
        memory = 512
      }
    }
  }
}
```

### 8. nomad/jobs/benthos-pipelines.nomad

```hcl
# modules/wazuh-mssp/nomad/jobs/benthos-pipelines.nomad
# Benthos data processing pipelines

job "benthos-pipelines" {
  datacenters = ["dc1"]
  type        = "service"
  namespace   = "platform"
  
  update {
    max_parallel      = 1
    health_check      = "checks"
    min_healthy_time  = "30s"
    healthy_deadline  = "5m"
    auto_revert       = true
  }
  
  # Webhook ingestion pipeline
  group "webhook-ingress" {
    count = 3
    
    network {
      mode = "bridge"
      
      port "http" {
        to = 4195
      }
      
      port "metrics" {
        to = 4196
      }
    }
    
    service {
      name = "benthos-webhook-ingress"
      port = "http"
      
      tags = [
        "traefik.enable=true",
        "traefik.http.routers.webhooks.rule=Host(`webhooks.${NOMAD_META_platform_domain}`)",
        "traefik.http.routers.webhooks.tls=true",
        "traefik.http.routers.webhooks.tls.certresolver=letsencrypt",
      ]
      
      connect {
        sidecar_service {
          proxy {
            upstreams {
              destination_name = "nats"
              local_bind_port  = 4222
            }
          }
        }
      }
      
      check {
        name     = "webhook-ingress-health"
        type     = "http"
        path     = "/ready"
        interval = "10s"
        timeout  = "2s"
      }
    }
    
    service {
      name = "benthos-webhook-metrics"
      port = "metrics"
      tags = ["prometheus"]
    }
    
    task "benthos" {
      driver = "docker"
      
      config {
        image = "jeffail/benthos:4.20"
        ports = ["http", "metrics"]
        
        args = [
          "-c", "/local/benthos.yaml",
        ]
      }
      
      vault {
        policies = ["benthos"]
      }
      
      template {
        data = file("${NOMAD_META_benthos_configs}/webhook-ingress.yaml")
        destination = "local/benthos.yaml"
      }
      
      template {
        data = <<EOF
NATS_URL=nats://localhost:4222
{{- with secret "kv/data/nats/creds/benthos" }}
NATS_CREDS={{ .Data.data.creds | toJSON }}
{{- end }}
{{- with secret "kv/data/webhooks/secrets" }}
JWT_SECRET={{ .Data.data.jwt_secret }}
STRIPE_WEBHOOK_SECRET={{ .Data.data.stripe_secret }}
AUTHENTIK_WEBHOOK_SECRET={{ .Data.data.authentik_secret }}
{{- end }}
LOG_LEVEL=INFO
EOF
        
        destination = "secrets/.env"
        env         = true
      }
      
      template {
        data = <<EOF
{{ with secret "kv/data/nats/creds/benthos" }}{{ .Data.data.creds }}{{ end }}
EOF
        destination = "secrets/nats.creds"
      }
      
      resources {
        cpu    = 500
        memory = 512
      }
    }
  }
  
  # Event router pipeline
  group "event-router" {
    count = 2
    
    network {
      mode = "bridge"
      
      port "metrics" {
        to = 4196
      }
    }
    
    service {
      name = "benthos-event-router"
      port = "metrics"
      
      tags = ["benthos", "router", "prometheus"]
      
      connect {
        sidecar_service {
          proxy {
            upstreams {
              destination_name = "nats"
              local_bind_port  = 4222
            }
            
            upstreams {
              destination_name = "temporal-frontend"
              local_bind_port  = 7233
            }
            
            upstreams {
              destination_name = "wazuh-api"
              local_bind_port  = 8000
            }
          }
        }
      }
    }
    
    task "benthos" {
      driver = "docker"
      
      config {
        image = "jeffail/benthos:4.20"
        ports = ["metrics"]
        
        args = [
          "-c", "/local/benthos.yaml",
        ]
      }
      
      vault {
        policies = ["benthos"]
      }
      
      template {
        data = file("${NOMAD_META_benthos_configs}/event-router.yaml")
        destination = "local/benthos.yaml"
      }
      
      template {
        data = <<EOF
NATS_URL=nats://localhost:4222
{{- with secret "kv/data/nats/creds/benthos" }}
NATS_CREDS={{ .Data.data.creds | toJSON }}
{{- end }}
TEMPORAL_ADDRESS=localhost:7233
API_URL=http://localhost:8000
{{- with secret "kv/data/api/tokens/benthos" }}
API_TOKEN={{ .Data.data.token }}
{{- end }}
JAEGER_AGENT=jaeger.service.consul:6831
LOG_LEVEL=INFO
EOF
        
        destination = "secrets/.env"
        env         = true
      }
      
      template {
        data = <<EOF
{{ with secret "kv/data/nats/creds/benthos" }}{{ .Data.data.creds }}{{ end }}
EOF
        destination = "secrets/nats.creds"
      }
      
      resources {
        cpu    = 1000
        memory = 1024
      }
    }
  }
  
  # Metrics processor pipeline
  group "metrics-processor" {
    count = 2
    
    network {
      mode = "bridge"
      
      port "metrics" {
        to = 4196
      }
    }
    
    service {
      name = "benthos-metrics-processor"
      port = "metrics"
      
      tags = ["benthos", "metrics", "prometheus"]
      
      connect {
        sidecar_service {
          proxy {
            upstreams {
              destination_name = "nats"
              local_bind_port  = 4222
            }
            
            upstreams {
              destination_name = "prometheus"
              local_bind_port  = 9090
            }
            
            upstreams {
              destination_name = "postgres"
              local_bind_port  = 5432
            }
          }
        }
      }
    }
    
    task "benthos" {
      driver = "docker"
      
      config {
        image = "jeffail/benthos:4.20"
        ports = ["metrics"]
        
        args = [
          "-c", "/local/benthos.yaml",
        ]
      }
      
      vault {
        policies = ["benthos"]
      }
      
      template {
        data = file("${NOMAD_META_benthos_configs}/metrics-processor.yaml")
        destination = "local/benthos.yaml"
      }
      
      template {
        data = <<EOF
NATS_URL=nats://localhost:4222
{{- with secret "kv/data/nats/creds/benthos" }}
NATS_CREDS={{ .Data.data.creds | toJSON }}
{{- end }}
PROMETHEUS_URL=http://localhost:9090
{{- with secret "database/creds/metrics" }}
DATABASE_URL=postgresql://{{ .Data.username }}:{{ .Data.password }}@localhost:5432/wazuh_metrics
{{- end }}
LOG_LEVEL=INFO
EOF
        
        destination = "secrets/.env"
        env         = true
      }
      
      template {
        data = <<EOF
{{ with secret "kv/data/nats/creds/benthos" }}{{ .Data.data.creds }}{{ end }}
EOF
        destination = "secrets/nats.creds"
      }
      
      resources {
        cpu    = 1000
        memory = 1024
      }
    }
  }
}
```

### 9. nomad/packs/wazuh-customer/pack.hcl

```hcl
# modules/wazuh-mssp/nomad/packs/wazuh-customer/pack.hcl
# Nomad Pack for customer Wazuh deployments

job "wazuh-customer-[[.customer.id]]" {
  datacenters = [[ .wazuh.datacenters | toStringList ]]
  type        = "service"
  namespace   = "customer-[[.customer.id]]"
  
  meta {
    customer_id   = "[[ .customer.id ]]"
    customer_name = "[[ .customer.name ]]"
    tier         = "[[ .customer.tier ]]"
    created_at   = "[[ now ]]"
  }
  
  constraint {
    attribute = "${meta.customer_isolation}"
    value     = "true"
  }
  
  group "indexer" {
    count = [[ .wazuh.indexer_count ]]
    
    constraint {
      distinct_hosts = true
    }
    
    volume "indexer-data" {
      type      = "csi"
      source    = "indexer-data-[[.customer.id]]"
      read_only = false
      
      mount_options {
        fs_type = "ext4"
      }
    }
    
    network {
      mode = "bridge"
      
      port "http" {
        to = 9200
      }
      
      port "transport" {
        to = 9300
      }
    }
    
    service {
      name = "wazuh-indexer-[[.customer.id]]"
      port = "http"
      
      tags = ["wazuh", "indexer", "customer-[[.customer.id]]"]
      
      meta {
        customer_id = "[[ .customer.id ]]"
        component   = "indexer"
      }
      
      connect {
        sidecar_service {
          proxy {
            config {
              # Allow CCS queries from central indexer
              local_service_address = "shared.  GetInternalHostname:9200"
            }
          }
        }
      }
      
      check {
        name     = "indexer-health"
        type     = "http"
        path     = "/_cluster/health"
        interval = "30s"
        timeout  = "5s"
        
        check_restart {
          limit = 3
          grace = "90s"
        }
      }
    }
    
    task "indexer" {
      driver = "docker"
      
      config {
        image = "wazuh/wazuh-indexer:[[ .wazuh.version ]]"
        ports = ["http", "transport"]
        
        volumes = [
          "local/opensearch.yml:/usr/share/wazuh-indexer/config/opensearch.yml",
          "secrets/certs:/usr/share/wazuh-indexer/config/certs:ro",
        ]
        
        ulimit {
          memlock = "-1"
          nofile  = "65536"
          nproc   = "4096"
        }
      }
      
      volume_mount {
        volume      = "indexer-data"
        destination = "/var/lib/wazuh-indexer"
      }
      
      vault {
        policies = ["wazuh-customer"]
      }
      
      template {
        data = <<EOF
network.host: {{ env "NOMAD_IP_http" }}
node.name: {{ env "NOMAD_TASK_NAME" }}-{{ env "NOMAD_ALLOC_INDEX" }}
cluster.name: wazuh-cluster-[[ .customer.id ]]
node.master: true
node.data: true
node.ingest: true

cluster.initial_master_nodes:
[[ range $i := loop .wazuh.indexer_count ]]
  - wazuh-customer-[[ $.customer.id ]][{{ $i }}]
[[ end ]]

discovery.seed_hosts:
[[ range service (print "wazuh-indexer-" .customer.id) ]]
  - {{ .Address }}:9300
[[ end ]]

# Cross-cluster search configuration
cluster.remote:
  ccs:
    seeds: 
[[ range service "ccs-wazuh-indexer" ]]
      - {{ .Address }}:9300
[[ end ]]
    skip_unavailable: true

# Security configuration
plugins.security.ssl.transport.pemcert_filepath: certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false

plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath: certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: certs/root-ca.pem

plugins.security.authcz.admin_dn:
  - CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US

plugins.security.nodes_dn:
  - CN=wazuh-indexer-[[ .customer.id ]],OU=Wazuh,O=Wazuh,L=California,C=US
  - CN=ccs-wazuh-indexer,OU=Wazuh,O=Wazuh,L=California,C=US

# Resource limits based on tier
[[ if eq .customer.tier "starter" ]]
indices.memory.index_buffer_size: 10%
indices.memory.min_index_buffer_size: 48mb
[[ else if eq .customer.tier "pro" ]]
indices.memory.index_buffer_size: 15%
indices.memory.min_index_buffer_size: 96mb
[[ else ]]
indices.memory.index_buffer_size: 20%
indices.memory.min_index_buffer_size: 128mb
[[ end ]]

# Paths
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer
EOF
        
        destination = "local/opensearch.yml"
      }
      
      template {
        data = <<EOF
{{ with secret (printf "pki/issue/wazuh-indexer common_name=wazuh-indexer-%s.node.consul" (env "NOMAD_META_customer_id")) }}
{{ .Data.certificate }}
{{ end }}
EOF
        destination = "secrets/certs/indexer.pem"
      }
      
      template {
        data = <<EOF
{{ with secret (printf "pki/issue/wazuh-indexer common_name=wazuh-indexer-%s.node.consul" (env "NOMAD_META_customer_id")) }}
{{ .Data.private_key }}
{{ end }}
EOF
        destination = "secrets/certs/indexer-key.pem"
      }
      
      template {
        data = <<EOF
{{ with secret "pki/cert/ca" }}
{{ .Data.certificate }}
{{ end }}
EOF
        destination = "secrets/certs/root-ca.pem"
      }
      
      template {
        data = <<EOF
{{ with secret (printf "kv/data/customers/%s/wazuh/indexer" (env "NOMAD_META_customer_id")) }}
{{ .Data.data.admin_password | toJSON }}
{{ end }}
EOF
        destination = "secrets/admin-password"
      }
      
      env {
        OPENSEARCH_JAVA_OPTS = "-Xms[[ .resources.indexer.memory_heap ]] -Xmx[[ .resources.indexer.memory_heap ]]"
      }
      
      resources {
        cpu    = [[ .resources.indexer.cpu ]]
        memory = [[ .resources.indexer.memory ]]
      }
    }
  }
  
  group "server" {
    count = [[ .wazuh.server_count ]]
    
    network {
      mode = "bridge"
      
      port "api" {
        to = 55000
      }
      
      port "agent" {
        static = 1514
        to     = 1514
      }
      
      port "syslog" {
        static = 514
        to     = 514
      }
    }
    
    service {
      name = "wazuh-server-[[.customer.id]]"
      port = "api"
      
      tags = ["wazuh", "server", "customer-[[.customer.id]]"]
      
      meta {
        customer_id = "[[ .customer.id ]]"
        component   = "server"
      }
      
      connect {
        sidecar_service {
          proxy {
            upstreams {
              destination_name = "wazuh-indexer-[[.customer.id]]"
              local_bind_port  = 9200
            }
          }
        }
      }
      
      check {
        name     = "wazuh-api-health"
        type     = "http"
        path     = "/security/user/authenticate"
        interval = "30s"
        timeout  = "5s"
        header {
          Authorization = ["Basic ${WAZUH_API_CREDS}"]
        }
      }
    }
    
    task "server" {
      driver = "docker"
      
      config {
        image = "wazuh/wazuh-manager:[[ .wazuh.version ]]"
        ports = ["api", "agent", "syslog"]
        
        volumes = [
          "local/ossec.conf:/var/ossec/etc/ossec.conf",
          "secrets/certs:/var/ossec/etc/certs:ro",
        ]
      }
      
      vault {
        policies = ["wazuh-customer"]
      }
      
      template {
        data = <<EOF
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
  </global>
  
  <cluster>
    <name>wazuh-cluster-[[ .customer.id ]]</name>
    <node_name>{{ env "NOMAD_TASK_NAME" }}-{{ env "NOMAD_ALLOC_INDEX" }}</node_name>
    <node_type>{{ if eq (env "NOMAD_ALLOC_INDEX") "0" }}master{{ else }}worker{{ end }}</node_type>
    <key>{{ with secret (printf "kv/data/customers/%s/wazuh/cluster" (env "NOMAD_META_customer_id")) }}{{ .Data.data.key }}{{ end }}</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
[[ range service (print "wazuh-server-" .customer.id) ]]
      <node>{{ .Address }}</node>
[[ end ]]
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>
  
  <api>
    <host>0.0.0.0</host>
    <port>55000</port>
    <https>yes</https>
    <https_cert>certs/api.crt</https_cert>
    <https_key>certs/api.key</https_key>
    <https_ca>certs/ca.crt</https_ca>
  </api>
  
  <!-- Alert forwarding to NATS -->
  <integration>
    <name>nats-alerts</name>
    <hook_url>http://benthos-event-router.service.consul:4195/alerts</hook_url>
    <level>3</level>
    <alert_format>json</alert_format>
    <options>{"customer_id": "[[ .customer.id ]]"}</options>
  </integration>
  
  <!-- Vulnerability detection -->
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>12h</interval>
    <run_on_start>yes</run_on_start>
    
[[ if ne .customer.tier "starter" ]]
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>jammy</os>
      <os>focal</os>
      <update_interval>6h</update_interval>
    </provider>
    
    <provider name="redhat">
      <enabled>yes</enabled>
      <update_from_year>2020</update_from_year>
      <update_interval>6h</update_interval>
    </provider>
[[ end ]]
  </vulnerability-detector>
  
  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin,/boot</directories>
    
[[ if eq .customer.tier "enterprise" ]]
    <directories realtime="yes">/var/www,/var/lib</directories>
[[ end ]]
  </syscheck>
  
  <!-- Log analysis -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  
  <!-- Rootcheck -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
  </rootcheck>
  
  <!-- Active response -->
  <active-response>
    <disabled>no</disabled>
    <ca_store>certs/ca.crt</ca_store>
  </active-response>
</ossec_config>
EOF
        
        destination = "local/ossec.conf"
      }
      
      template {
        data = <<EOF
#!/bin/bash
# Filebeat configuration for Wazuh

cat > /var/ossec/etc/filebeat.yml <<'FILEBEAT'
output.elasticsearch:
  hosts: ["localhost:9200"]
  protocol: https
  username: "admin"
  password: "{{ with secret (printf "kv/data/customers/%s/wazuh/indexer" (env "NOMAD_META_customer_id")) }}{{ .Data.data.admin_password }}{{ end }}"
  ssl.certificate_authorities: ["/var/ossec/etc/certs/ca.crt"]
  ssl.verification_mode: full
  
setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.ilm.overwrite: true
setup.ilm.enabled: false

filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
FILEBEAT

# Start filebeat
/var/ossec/bin/wazuh-control start
EOF
        
        destination = "local/start-filebeat.sh"
        perms       = "755"
      }
      
      template {
        data = <<EOF
{{ with secret (printf "kv/data/customers/%s/wazuh/api" (env "NOMAD_META_customer_id")) }}
WAZUH_API_CREDS={{ printf "%s:%s" .Data.data.username .Data.data.password | base64Encode }}
{{ end }}
EOF
        
        destination = "secrets/.env"
        env         = true
      }
      
      resources {
        cpu    = [[ .resources.server.cpu ]]
        memory = [[ .resources.server.memory ]]
      }
    }
  }
  
  [[ if .wazuh.dashboard_enabled ]]
  group "dashboard" {
    count = 1
    
    network {
      mode = "bridge"
      
      port "https" {
        to = 443
      }
    }
    
    service {
      name = "wazuh-dashboard-[[.customer.id]]"
      port = "https"
      
      tags = [
        "wazuh",
        "dashboard", 
        "customer-[[.customer.id]]",
        "traefik.enable=true",
        "traefik.http.routers.wazuh-[[.customer.id]].rule=Host(`[[.customer.subdomain]].[[.platform_domain]]`)",
        "traefik.http.routers.wazuh-[[.customer.id]].tls=true",
        "traefik.http.routers.wazuh-[[.customer.id]].tls.certresolver=letsencrypt",
      ]
      
      connect {
        sidecar_service {}
      }
      
      check {
        name     = "dashboard-health"
        type     = "http"
        protocol = "https"
        tls_skip_verify = true
        path     = "/app/wazuh"
        interval = "30s"
        timeout  = "5s"
      }
    }
    
    task "dashboard" {
      driver = "docker"
      
      config {
        image = "wazuh/wazuh-dashboard:[[ .wazuh.version ]]"
        ports = ["https"]
        
        volumes = [
          "local/opensearch_dashboards.yml:/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml",
          "local/wazuh.yml:/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml",
          "secrets/certs:/usr/share/wazuh-dashboard/certs:ro",
        ]
      }
      
      vault {
        policies = ["wazuh-customer"]
      }
      
      template {
        data = <<EOF
server.name: wazuh-dashboard-[[ .customer.id ]]
server.host: "0.0.0.0"
server.port: 443

opensearch.hosts: 
[[ range service (print "wazuh-indexer-" .customer.id) ]]
  - "https://{{ .Address }}:9200"
[[ end ]]

opensearch.ssl.verificationMode: certificate
opensearch.username: "kibanaserver"
opensearch.password: "{{ with secret (printf "kv/data/customers/%s/wazuh/dashboard" (env "NOMAD_META_customer_id")) }}{{ .Data.data.kibanaserver_password }}{{ end }}"

opensearch.requestHeadersWhitelist: [ authorization, securitytenant ]
opensearch_security.multitenancy.enabled: true
opensearch_security.multitenancy.tenants.preferred: ["Private", "Global"]
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
opensearch_security.cookie.secure: true

server.ssl.enabled: true
server.ssl.certificate: /usr/share/wazuh-dashboard/certs/dashboard.crt
server.ssl.key: /usr/share/wazuh-dashboard/certs/dashboard.key
opensearch.ssl.certificateAuthorities: ["/usr/share/wazuh-dashboard/certs/ca.crt"]

# SAML authentication
[[ if .authentik.enabled ]]
opensearch_security.auth.type: "saml"
server.xsrf.whitelist: ["/_opendistro/_security/saml/acs", "/_opendistro/_security/saml/logout"]
opensearch_security.saml.idp.metadata_url: "[[ .authentik.metadata_url ]]"
opensearch_security.saml.idp.entity_id: "[[ .authentik.entity_id ]]"
opensearch_security.saml.sp.entity_id: "wazuh-dashboard-[[ .customer.id ]]"
opensearch_security.saml.sp.signature_private_key_filepath: "/usr/share/wazuh-dashboard/certs/saml.key"
opensearch_security.saml.sp.signature_certificate_filepath: "/usr/share/wazuh-dashboard/certs/saml.crt"
opensearch_security.saml.sp.encryption_private_key_filepath: "/usr/share/wazuh-dashboard/certs/saml.key"
opensearch_security.saml.sp.encryption_certificate_filepath: "/usr/share/wazuh-dashboard/certs/saml.crt"
[[ end ]]
EOF
        
        destination = "local/opensearch_dashboards.yml"
      }
      
      template {
        data = <<EOF
hosts:
  - [[ .customer.name ]]:
      url: https://{{ range $i, $s := service (print "wazuh-server-" .customer.id) }}{{ if eq $i 0 }}{{ .Address }}{{ end }}{{ end }}
      port: 55000
      username: {{ with secret (printf "kv/data/customers/%s/wazuh/api" (env "NOMAD_META_customer_id")) }}{{ .Data.data.username }}{{ end }}
      password: {{ with secret (printf "kv/data/customers/%s/wazuh/api" (env "NOMAD_META_customer_id")) }}{{ .Data.data.password }}{{ end }}
      run_as: false
EOF
        
        destination = "local/wazuh.yml"
      }
      
      resources {
        cpu    = [[ .resources.dashboard.cpu ]]
        memory = [[ .resources.dashboard.memory ]]
      }
    }
  }
  [[ end ]]
}
```

### 10. /states/wazuh/base.sls

```yaml
# modules/wazuh-mssp//states/wazuh/base.sls
# Base Wazuh configuration state

{% set customer = ['.get']('customer', {}) %}
{% set wazuh = ['.get']('wazuh', {}) %}

# Wazuh repository
wazuh_repo:
  pkgrepo.managed:
    - name: deb https://packages.wazuh.com/4.x/apt/ stable main
    - file: /etc/apt/sources.list.d/wazuh.list
    - key_url: https://packages.wazuh.com/key/GPG-KEY-WAZUH
    - require_in:
      - pkg: wazuh_packages

# Install Wazuh components based on node role
wazuh_packages:
  pkg.installed:
    - pkgs:
      {% if 'indexer' in s.get('wazuh_role', []) %}
      - wazuh-indexer
      {% endif %}
      {% if 'server' in s.get('wazuh_role', []) %}
      - wazuh-manager
      - filebeat
      {% endif %}
      {% if 'dashboard' in s.get('wazuh_role', []) %}
      - wazuh-dashboard
      {% endif %}
    - version: {{ wazuh.get('version', '4.8.2') }}

# System tuning for Wazuh
wazuh_sysctl:
  sysctl.present:
    - names:
      - vm.max_map_count:
          value: 262144
      - fs.file-max:
          value: 65536
      - net.ipv4.tcp_tw_reuse:
          value: 1
      - net.ipv4.tcp_fin_timeout:
          value: 15

# Limits configuration
/etc/security/limits.d/wazuh.conf:
  file.managed:
    - contents: |
        wazuh-indexer soft nofile 65536
        wazuh-indexer hard nofile 65536
        wazuh-indexer soft nproc 4096
        wazuh-indexer hard nproc 4096
        wazuh soft nofile 65536
        wazuh hard nofile 65536

# Certificate directory
/etc/wazuh-certs:
  file.directory:
    - user: root
    - group: root
    - mode: 700
    - makedirs: True

# Download certificates from Vault
{% for cert_type in ['ca.pem', 'node.pem', 'node-key.pem'] %}
wazuh_cert_{{ cert_type }}:
  cmd.run:
    - name: |
        vault kv get -field={{ cert_type }} \
          secret/customers/{{ customer.id }}/certificates/{{ s['id'] }} \
          > /etc/wazuh-certs/{{ cert_type }}
    - creates: /etc/wazuh-certs/{{ cert_type }}
    - require:
      - file: /etc/wazuh-certs
{% endfor %}

# Set certificate permissions
wazuh_cert_permissions:
  file.managed:
    - names:
      - /etc/wazuh-certs/ca.pem:
        - mode: 644
      - /etc/wazuh-certs/node.pem:
        - mode: 644
      - /etc/wazuh-certs/node-key.pem:
        - mode: 600
    - require:
      - cmd: wazuh_cert_ca.pem
      - cmd: wazuh_cert_node.pem
      - cmd: wazuh_cert_node-key.pem

# Create wazuh user if not exists
wazuh_user:
  user.present:
    - name: wazuh
    - system: True
    - shell: /bin/false
    - home: /var/lib/wazuh
    - createhome: True
    - groups:
      - wazuh
    - require:
      - group: wazuh

wazuh_group:
  group.present:
    - name: wazuh
    - system: True

# Firewall rules based on role
{% if 'indexer' in s.get('wazuh_role', []) %}
wazuh_indexer_firewall:
  cmd.run:
    - names:
      - ufw allow 9200/tcp comment 'Wazuh Indexer API'
      - ufw allow 9300/tcp comment 'Wazuh Indexer Transport'
    - unless: ufw status | grep -E '9200|9300'
{% endif %}

{% if 'server' in s.get('wazuh_role', []) %}
wazuh_server_firewall:
  cmd.run:
    - names:
      - ufw allow 1514/tcp comment 'Wazuh Agent connection'
      - ufw allow 1514/udp comment 'Wazuh Agent connection UDP'
      - ufw allow 1515/tcp comment 'Wazuh Agent enrollment'
      - ufw allow 1516/tcp comment 'Wazuh Cluster'
      - ufw allow 55000/tcp comment 'Wazuh API'
      - ufw allow 514/udp comment 'Syslog'
    - unless: ufw status | grep -E '1514|1515|1516|55000|514'
{% endif %}

{% if 'dashboard' in s.get('wazuh_role', []) %}
wazuh_dashboard_firewall:
  cmd.run:
    - names:
      - ufw allow 443/tcp comment 'Wazuh Dashboard HTTPS'
    - unless: ufw status | grep 443
{% endif %}

# Monitoring
node_exporter_wazuh:
  file.managed:
    - name: /etc/systemd/system/node_exporter_wazuh.service
    - contents: |
        [Unit]
        Description=Node Exporter for Wazuh
        After=network.target
        
        [Service]
        Type=simple
        ExecStart=/usr/local/bin/node_exporter \
          --collector.textfile.directory=/var/lib/node_exporter/textfile_collector \
          --collector.systemd \
          --collector.processes \
          --web.listen-address=:9101
        Restart=on-failure
        
        [Install]
        WantedBy=multi-user.target

node_exporter_wazuh_service:
  service.running:
    - name: node_exporter_wazuh
    - enable: True
    - require:
      - file: node_exporter_wazuh

# Custom metrics collector
/usr/local/bin/wazuh-metrics-collector.sh:
  file.managed:
    - mode: 755
    - contents: |
        #!/bin/bash
        # Collect Wazuh metrics for Prometheus
        
        TEXTFILE_COLLECTOR_DIR="/var/lib/node_exporter/textfile_collector"
        mkdir -p "$TEXTFILE_COLLECTOR_DIR"
        
        # Collect based on role
        {% if 'server' in s.get('wazuh_role', []) %}
        # Agent count
        AGENT_COUNT=$(/var/ossec/bin/agent_control -l | grep -c "Active")
        echo "wazuh_active_agents $AGENT_COUNT" > "$TEXTFILE_COLLECTOR_DIR/wazuh.prom"
        
        # Queue size
        QUEUE_SIZE=$(find /var/ossec/queue/alerts -name "*.log" | wc -l)
        echo "wazuh_queue_size $QUEUE_SIZE" >> "$TEXTFILE_COLLECTOR_DIR/wazuh.prom"
        {% endif %}
        
        {% if 'indexer' in s.get('wazuh_role', []) %}
        # Index size
        INDICES_SIZE=$(curl -s -k -u admin:$ADMIN_PASSWORD https://localhost:9200/_cat/indices?bytes=b | awk '{sum+=$9} END {print sum}')
        echo "wazuh_indices_size_bytes $INDICES_SIZE" >> "$TEXTFILE_COLLECTOR_DIR/wazuh.prom"
        {% endif %}

# Cron job for metrics collection
wazuh_metrics_cron:
  cron.present:
    - name: /usr/local/bin/wazuh-metrics-collector.sh
    - minute: '*/5'
    - require:
      - file: /usr/local/bin/wazuh-metrics-collector.sh
```

### 11. temporal/workflows/customer_provisioning.go

```go
// modules/wazuh-mssp/temporal/workflows/customer_provisioning.go
package workflows

import (
    "context"
    "fmt"
    "time"
    
    "go.temporal.io/sdk/temporal"
    "go.temporal.io/sdk/workflow"
    
    "github.com/wazuh-mssp/temporal/activities"
    "github.com/wazuh-mssp/temporal/models"
)

// CustomerProvisioningWorkflow orchestrates the complete customer onboarding process
func CustomerProvisioningWorkflow(ctx workflow.Context, request models.ProvisioningRequest) error {
    logger := workflow.GetLogger(ctx)
    logger.Info("Starting customer provisioning workflow", 
        "customerID", request.CustomerID,
        "companyName", request.CompanyName,
        "tier", request.Tier)
    
    // Configure activity options with retries
    ao := workflow.ActivityOptions{
        StartToCloseTimeout: 10 * time.Minute,
        RetryPolicy: &temporal.RetryPolicy{
            InitialInterval:    time.Second,
            BackoffCoefficient: 2.0,
            MaximumInterval:    time.Minute,
            MaximumAttempts:    3,
        },
    }
    ctx = workflow.WithActivityOptions(ctx, ao)
    
    // Initialize provisioning state for potential rollback
    var provisioningState models.ProvisioningState
    provisioningState.CustomerID = request.CustomerID
    provisioningState.StartTime = workflow.Now(ctx)
    
    // Create a saga for compensation
    var compensations []func(workflow.Context) error
    
    // Step 1: Validate the provisioning request
    logger.Info("Validating provisioning request")
    var validation models.ValidationResult
    err := workflow.ExecuteActivity(ctx, activities.ValidateProvisioningRequest, request).Get(ctx, &validation)
    if err != nil {
        return fmt.Errorf("validation failed: %w", err)
    }
    
    if !validation.Valid {
        return temporal.NewApplicationError(
            fmt.Sprintf("Invalid provisioning request: %s", validation.Reason),
            "INVALID_REQUEST",
        )
    }
    
    // Step 2: Check and allocate resources
    logger.Info("Allocating resources for customer")
    var allocation models.ResourceAllocation
    err = workflow.ExecuteActivity(ctx, activities.AllocateResources, models.AllocationRequest{
        CustomerID: request.CustomerID,
        Tier:       request.Tier,
    }).Get(ctx, &allocation)
    if err != nil {
        return fmt.Errorf("resource allocation failed: %w", err)
    }
    
    provisioningState.ResourcesAllocated = true
    provisioningState.AllocationID = allocation.ID
    
    // Add compensation
    compensations = append(compensations, func(ctx workflow.Context) error {
        return workflow.ExecuteActivity(ctx, activities.ReleaseResources, allocation.ID).Get(ctx, nil)
    })
    
    // Step 3: Create network infrastructure
    logger.Info("Creating network infrastructure")
    var network models.NetworkConfig
    err = workflow.ExecuteActivity(ctx, activities.CreateNetworkInfrastructure, models.NetworkRequest{
        CustomerID: request.CustomerID,
        VLANID:     allocation.VLANID,
        Subnet:     allocation.NetworkSubnet,
    }).Get(ctx, &network)
    if err != nil {
        return compensate(ctx, compensations, fmt.Errorf("network creation failed: %w", err))
    }
    
    provisioningState.NetworkCreated = true
    compensations = append(compensations, func(ctx workflow.Context) error {
        return workflow.ExecuteActivity(ctx, activities.DeleteNetworkInfrastructure, network.ID).Get(ctx, nil)
    })
    
    // Step 4: Deploy infrastructure with Terraform
    logger.Info("Deploying infrastructure with Terraform")
    terraformCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
        StartToCloseTimeout: 30 * time.Minute,
        HeartbeatTimeout:    time.Minute,
        RetryPolicy: &temporal.RetryPolicy{
            MaximumAttempts: 1, // Don't retry Terraform to avoid partial state
        },
    })
    
    var infrastructure models.InfrastructureResult
    err = workflow.ExecuteActivity(terraformCtx, activities.DeployTerraformInfrastructure, models.TerraformRequest{
        CustomerID: request.CustomerID,
        Module:     "customer-environment",
        Variables: map[string]interface{}{
            "customer_id":     request.CustomerID,
            "customer_name":   request.CompanyName,
            "tier":           request.Tier,
            "subdomain":      request.Subdomain,
            "network_config": network,
            "resources":      allocation.Resources,
        },
    }).Get(ctx, &infrastructure)
    
    if err != nil {
        return compensate(ctx, compensations, fmt.Errorf("terraform deployment failed: %w", err))
    }
    
    provisioningState.InfrastructureDeployed = true
    provisioningState.InfrastructureID = infrastructure.ID
    compensations = append(compensations, func(ctx workflow.Context) error {
        return workflow.ExecuteActivity(ctx, activities.DestroyTerraformInfrastructure, infrastructure.ID).Get(ctx, nil)
    })
    
    // Step 5: Configure platform services in parallel
    logger.Info("Configuring platform services")
    var futures []workflow.Future
    
    // Configure Nomad namespace and policies
    futures = append(futures, workflow.ExecuteActivity(ctx, 
        activities.ConfigureNomadNamespace, 
        models.NomadNamespaceRequest{
            CustomerID: request.CustomerID,
            Quotas:     allocation.NomadQuotas,
        }))
    
    // Configure NATS account
    futures = append(futures, workflow.ExecuteActivity(ctx, 
        activities.ConfigureNATSAccount, 
        models.NATSAccountRequest{
            CustomerID: request.CustomerID,
            Limits:     allocation.NATSLimits,
        }))
    
    // Configure Vault policies and secrets
    futures = append(futures, workflow.ExecuteActivity(ctx, 
        activities.ConfigureVaultSecrets, 
        models.VaultSecretsRequest{
            CustomerID: request.CustomerID,
            Secrets:    generateInitialSecrets(request),
        }))
    
    // Configure Consul services
    futures = append(futures, workflow.ExecuteActivity(ctx, 
        activities.ConfigureConsulServices, 
        models.ConsulServicesRequest{
            CustomerID: request.CustomerID,
            Services:   getCustomerServices(request.Tier),
        }))
    
    // Wait for all parallel activities to complete
    for i, future := range futures {
        if err := future.Get(ctx, nil); err != nil {
            return compensate(ctx, compensations, fmt.Errorf("platform service configuration %d failed: %w", i, err))
        }
    }
    
    provisioningState.PlatformServicesConfigured = true
    
    // Step 6: Deploy Wazuh components using Nomad
    logger.Info("Deploying Wazuh components")
    err = workflow.ExecuteActivity(ctx, activities.DeployWazuhComponents, models.WazuhDeploymentRequest{
        CustomerID:   request.CustomerID,
        Tier:        request.Tier,
        Version:     request.WazuhVersion,
        NetworkConfig: network,
        Resources:    allocation.Resources,
    }).Get(ctx, nil)
    
    if err != nil {
        return compensate(ctx, compensations, fmt.Errorf("wazuh deployment failed: %w", err))
    }
    
    provisioningState.WazuhDeployed = true
    compensations = append(compensations, func(ctx workflow.Context) error {
        return workflow.ExecuteActivity(ctx, activities.UndeployWazuhComponents, request.CustomerID).Get(ctx, nil)
    })
    
    // Step 7: Configure  states for the customer
    logger.Info("Applying  configuration")
    err = workflow.ExecuteActivity(ctx, activities.ApplyConfiguration, models.ConfigRequest{
        CustomerID: request.CustomerID,
        Targets:    infrastructure.NodeIDs,
        States: []string{
            "wazuh.base",
            "wazuh.certificates", 
            "wazuh.customer",
            "monitoring.customer",
        },
    }).Get(ctx, nil)
    
    if err != nil {
        return compensate(ctx, compensations, fmt.Errorf(" configuration failed: %w", err))
    }
    
    // Step 8: Wait for services to be healthy
    logger.Info("Waiting for services to become healthy")
    healthCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
        StartToCloseTimeout: 10 * time.Minute,
        RetryPolicy: &temporal.RetryPolicy{
            InitialInterval:    10 * time.Second,
            BackoffCoefficient: 1.5,
            MaximumInterval:    time.Minute,
            MaximumAttempts:    30,
        },
    })
    
    var health models.HealthStatus
    err = workflow.ExecuteActivity(healthCtx, activities.CheckServicesHealth, models.HealthCheckRequest{
        CustomerID: request.CustomerID,
        Services: []string{
            fmt.Sprintf("wazuh-indexer-%s", request.CustomerID),
            fmt.Sprintf("wazuh-server-%s", request.CustomerID),
            fmt.Sprintf("wazuh-dashboard-%s", request.CustomerID),
        },
        RequireAll: true,
    }).Get(ctx, &health)
    
    if err != nil {
        return compensate(ctx, compensations, fmt.Errorf("services failed health check: %w", err))
    }
    
    // Step 9: Create Authentik application and configure SSO
    logger.Info("Configuring Authentik SSO")
    var authentikApp models.AuthentikApplication
    err = workflow.ExecuteActivity(ctx, activities.CreateAuthentikApplication, models.AuthentikRequest{
        CustomerID:   request.CustomerID,
        CompanyName:  request.CompanyName,
        Subdomain:    request.Subdomain,
        AdminEmail:   request.AdminEmail,
        DashboardURL: fmt.Sprintf("https://%s.%s", request.Subdomain, request.PlatformDomain),
        CallbackURLs: []string{
            fmt.Sprintf("https://%s.%s/oauth2/callback", request.Subdomain, request.PlatformDomain),
            fmt.Sprintf("https://%s.%s/_opendistro/_security/saml/acs", request.Subdomain, request.PlatformDomain),
        },
    }).Get(ctx, &authentikApp)
    
    if err != nil {
        // Non-critical, log but continue
        logger.Error("Failed to configure Authentik SSO", "error", err)
    } else {
        provisioningState.SSOConfigured = true
        compensations = append(compensations, func(ctx workflow.Context) error {
            return workflow.ExecuteActivity(ctx, activities.DeleteAuthentikApplication, authentikApp.ID).Get(ctx, nil)
        })
    }
    
    // Step 10: Initialize customer data
    logger.Info("Initializing customer data")
    err = workflow.ExecuteActivity(ctx, activities.InitializeCustomerData, models.CustomerDataRequest{
        CustomerID: request.CustomerID,
        InitialData: models.InitialCustomerData{
            ComplianceTemplates: getComplianceTemplates(request.Tier),
            AlertRules:         getDefaultAlertRules(request.Tier),
            Dashboards:         getDefaultDashboards(request.Tier),
            AgentGroups:        getDefaultAgentGroups(),
        },
    }).Get(ctx, nil)
    
    if err != nil {
        // Non-critical, log but continue
        logger.Error("Failed to initialize customer data", "error", err)
    }
    
    // Step 11: Send welcome email
    logger.Info("Sending welcome email")
    err = workflow.ExecuteActivity(ctx, activities.SendWelcomeEmail, models.WelcomeEmailRequest{
        CustomerID:         request.CustomerID,
        AdminEmail:         request.AdminEmail,
        AdminName:          request.AdminName,
        CompanyName:        request.CompanyName,
        DashboardURL:       fmt.Sprintf("https://%s.%s", request.Subdomain, request.PlatformDomain),
        APIEndpoint:        fmt.Sprintf("https://api.%s/v1/customers/%s", request.PlatformDomain, request.CustomerID),
        AgentEnrollmentKey: infrastructure.AgentEnrollmentKey,
        DocumentationURL:   fmt.Sprintf("https://docs.%s", request.PlatformDomain),
    }).Get(ctx, nil)
    
    if err != nil {
        // Non-critical, log but continue
        logger.Error("Failed to send welcome email", "error", err)
    }
    
    // Step 12: Record provisioning completion
    provisioningState.CompletedAt = workflow.Now(ctx)
    provisioningState.Success = true
    
    err = workflow.ExecuteActivity(ctx, activities.RecordProvisioningCompletion, provisioningState).Get(ctx, nil)
    if err != nil {
        logger.Error("Failed to record provisioning completion", "error", err)
    }
    
    // Step 13: Start monitoring workflow
    logger.Info("Starting customer monitoring workflow")
    childCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{
        WorkflowID: fmt.Sprintf("monitor-%s", request.CustomerID),
        // Don't wait for the child workflow to complete
        ParentClosePolicy: temporal.ParentClosePolicyAbandon,
    })
    
    err = workflow.ExecuteChildWorkflow(childCtx, CustomerMonitoringWorkflow, models.MonitoringConfig{
        CustomerID:      request.CustomerID,
        Tier:           request.Tier,
        CheckInterval:   5 * time.Minute,
        AlertThresholds: getAlertThresholds(request.Tier),
    }).GetChildWorkflowExecution().Get(ctx, nil)
    
    if err != nil {
        logger.Error("Failed to start monitoring workflow", "error", err)
    }
    
    logger.Info("Customer provisioning completed successfully", 
        "customerID", request.CustomerID,
        "duration", workflow.Now(ctx).Sub(provisioningState.StartTime))
    
    return nil
}

// compensate executes compensation functions in reverse order
func compensate(ctx workflow.Context, compensations []func(workflow.Context) error, originalErr error) error {
    logger := workflow.GetLogger(ctx)
    logger.Error("Executing compensation due to error", "originalError", originalErr)
    
    // Execute compensations in reverse order
    for i := len(compensations) - 1; i >= 0; i-- {
        if err := compensations[i](ctx); err != nil {
            logger.Error("Compensation failed", "index", i, "error", err)
            // Continue with other compensations
        }
    }
    
    return originalErr
}

// Helper functions
func generateInitialSecrets(request models.ProvisioningRequest) map[string]string {
    return map[string]string{
        "wazuh_api_password":        generateSecurePassword(32),
        "wazuh_cluster_key":         generateSecurePassword(32),
        "indexer_admin_password":    generateSecurePassword(24),
        "kibanaserver_password":     generateSecurePassword(24),
        "agent_enrollment_password": generateSecurePassword(16),
    }
}

func getCustomerServices(tier string) []string {
    services := []string{
        "wazuh-indexer",
        "wazuh-server",
        "wazuh-dashboard",
    }
    
    if tier == "enterprise" {
        services = append(services, 
            "wazuh-reporting",
            "wazuh-integrator",
        )
    }
    
    return services
}

func getComplianceTemplates(tier string) []string {
    templates := []string{"PCI-DSS", "CIS"}
    
    if tier == "pro" || tier == "enterprise" {
        templates = append(templates, "HIPAA", "GDPR", "ISO-27001")
    }
    
    if tier == "enterprise" {
        templates = append(templates, "SOC2", "NIST", "Custom")
    }
    
    return templates
}

func getDefaultAlertRules(tier string) []models.AlertRule {
    rules := []models.AlertRule{
        {
            Name:        "Failed Authentication",
            Level:       5,
            Frequency:   5,
            TimeWindow:  300,
            EmailAlert:  true,
        },
        {
            Name:        "Malware Detected",
            Level:       12,
            Frequency:   1,
            TimeWindow:  60,
            EmailAlert:  true,
        },
    }
    
    if tier == "pro" || tier == "enterprise" {
        rules = append(rules, models.AlertRule{
            Name:        "Compliance Violation",
            Level:       10,
            Frequency:   1,
            TimeWindow:  3600,
            EmailAlert:  true,
            WebhookURL:  "https://api.${PLATFORM_DOMAIN}/webhooks/compliance",
        })
    }
    
    return rules
}

func getDefaultDashboards(tier string) []string {
    dashboards := []string{
        "Security Events Overview",
        "Agent Status",
        "Top Alerts",
    }
    
    if tier == "pro" || tier == "enterprise" {
        dashboards = append(dashboards,
            "Compliance Dashboard",
            "Vulnerability Assessment",
            "File Integrity Monitoring",
        )
    }
    
    if tier == "enterprise" {
        dashboards = append(dashboards,
            "Executive Summary",
            "Threat Intelligence",
            "Custom Analytics",
        )
    }
    
    return dashboards
}

func getDefaultAgentGroups() []models.AgentGroup {
    return []models.AgentGroup{
        {
            Name:        "default",
            Description: "Default agent group",
        },
        {
            Name:        "servers",
            Description: "Server agents",
        },
        {
            Name:        "workstations", 
            Description: "Workstation agents",
        },
    }
}

func getAlertThresholds(tier string) models.AlertThresholds {
    base := models.AlertThresholds{
        CPUUsage:           80,
        MemoryUsage:        85,
        DiskUsage:          90,
        AgentDisconnected:  300, // 5 minutes
        IndexerLatency:     1000, // 1 second
        QueueSize:          10000,
    }
    
    if tier == "enterprise" {
        // More sensitive thresholds for enterprise
        base.CPUUsage = 70
        base.MemoryUsage = 75
        base.IndexerLatency = 500
    }
    
    return base
}

func generateSecurePassword(length int) string {
    // Implementation would use crypto/rand
    // This is a placeholder
    return fmt.Sprintf("SecurePassword%d!", length)
}
```

### 12. benthos/configs/event-router.yaml

```yaml
# modules/wazuh-mssp/benthos/configs/event-router.yaml
# Benthos configuration for event routing to Temporal workflows

input:
  broker:
    inputs:
      # Subscribe to webhook events
      - nats_jetstream:
          urls:
            - ${NATS_URL}
          queue: event-router-webhooks
          subject: webhooks.>
          durable: event-router-webhooks
          deliver: all
          ack_wait: 30s
          max_ack_pending: 100
          auth:
            nkey_file: ${NATS_CREDS}
      
      # Subscribe to customer events
      - nats_jetstream:
          urls:
            - ${NATS_URL}
          queue: event-router-customer
          subject: customer.*.events
          durable: event-router-customer
          deliver: all
          ack_wait: 30s
          auth:
            nkey_file: ${NATS_CREDS}
      
      # Subscribe to platform events
      - nats_jetstream:
          urls:
            - ${NATS_URL}
          queue: event-router-platform
          subject: platform.events
          durable: event-router-platform
          deliver: all
          ack_wait: 30s
          auth:
            nkey_file: ${NATS_CREDS}

pipeline:
  processors:
    # Parse JSON message
    - try:
        - json:
            operator: parse
    
    # Extract routing metadata
    - label: extract_routing_info
      mapping: |
        root = this
        meta event_type = this.type.or(this.event_type).or(this.webhook_metadata.event_type).or("")
        meta customer_id = this.customer_id.or(this.data.customer_id).or("")
        meta priority = this.priority.or("normal")
        meta source = this.webhook_metadata.provider.or("internal")
        meta trace_id = this.trace_id.or(uuid_v4())
    
    # Route to appropriate workflow
    - label: determine_workflow
      switch:
        cases:
          # Customer provisioning from Authentik
          - check: |
              metadata("event_type") == "user_write" && 
              this.webhook_metadata.provider == "authentik" &&
              this.context.event == "user_created" &&
              this.context.model_name == "user"
            processors:
              - mapping: |
                  meta workflow_type = "CustomerProvisioningWorkflow"
                  meta task_queue = "provisioning"
                  meta workflow_id = "provision-" + this.context.customer_id
                  root.workflow_input = {
                    "customer_id": this.context.customer_id,
                    "company_name": this.context.company_name,
                    "subdomain": this.context.subdomain,
                    "tier": this.context.subscription_tier.or("starter"),
                    "admin_email": this.context.email,
                    "admin_name": this.context.name,
                    "authentik_data": {
                      "user_pk": this.context.pk,
                      "username": this.context.username
                    }
                  }
          
          # Payment successful - activate or upgrade
          - check: |
              metadata("event_type") == "checkout.session.completed" ||
              metadata("event_type") == "invoice.payment_succeeded"
            processors:
              - mapping: |
                  meta workflow_type = "PaymentProcessingWorkflow"
                  meta task_queue = "billing"
                  meta workflow_id = "payment-" + this.data.object.id
                  root.workflow_input = {
                    "payment_id": this.data.object.id,
                    "customer_id": this.data.object.metadata.customer_id,
                    "amount": this.data.object.amount_total.or(this.data.object.amount_paid),
                    "currency": this.data.object.currency,
                    "subscription_id": this.data.object.subscription,
                    "invoice_id": this.data.object.invoice,
                    "payment_status": this.data.object.payment_status.or("succeeded")
                  }
          
          # Customer scaling request
          - check: metadata("event_type") == "customer.scale"
            processors:
              - mapping: |
                  meta workflow_type = "CustomerScalingWorkflow"
                  meta task_queue = "operations"
                  meta workflow_id = "scale-" + metadata("customer_id") + "-" + timestamp_unix()
                  root.workflow_input = {
                    "customer_id": metadata("customer_id"),
                    "current_tier": this.current_tier,
                    "requested_tier": this.requested_tier,
                    "scaling_type": this.scaling_type.or("vertical"),
                    "effective_date": this.effective_date.or(now())
                  }
          
          # Backup operations
          - check: metadata("event_type") == "backup.scheduled"
            processors:
              - mapping: |
                  meta workflow_type = "BackupWorkflow"
                  meta task_queue = "operations"
                  meta workflow_id = "backup-" + metadata("customer_id") + "-" + format_timestamp("2006-01-02")
                  root.workflow_input = {
                    "customer_id": metadata("customer_id"),
                    "backup_type": this.backup_type.or("incremental"),
                    "retention_days": this.retention_days.or(30)
                  }
          
          # Alert aggregation - don't send to Temporal
          - check: metadata("event_type") == "wazuh.alert"
            processors:
              - mapping: |
                  meta route_to = "metrics"
                  meta nats_subject = "metrics.wazuh.alerts"
                  root = this
          
          # Health check events
          - check: metadata("event_type") == "health.check"
            processors:
              - mapping: |
                  meta route_to = "monitoring"
                  meta nats_subject = "monitoring.health"
                  root = this
          
          # Default - send to dead letter queue
          - check: "true"
            processors:
              - mapping: |
                  meta route_to = "dlq"
                  root.error = "Unknown event type: " + metadata("event_type")
                  root.original_message = this
    
    # Add workflow metadata
    - label: add_workflow_metadata
      bloblang: |
        if metadata("workflow_type").length() > 0 {
          root.workflow_metadata = {
            "workflow_type": metadata("workflow_type"),
            "workflow_id": metadata("workflow_id"),
            "task_queue": metadata("task_queue"),
            "priority": metadata("priority"),
            "trace_id": metadata("trace_id"),
            "timestamp": now()
          }
        }
    
    # Add retry tracking
    - label: add_retry_tracking
      metadata:
        operator: set
        key: retry_count
        value: ${!count:retry_count}.or(0)

output:
  switch:
    retry_until_success: false
    cases:
      # Route to Temporal via temporal-client binary
      - check: metadata("workflow_type").length() > 0
        output:
          retry:
            max_retries: 3
            backoff:
              initial_interval: 1s
              max_interval: 30s
              max_elapsed_time: 5m
            output:
              label: temporal_workflow_trigger
              subprocess:
                name: temporal-cli
                codec: lines
                spawn_variant:
                  command: /usr/local/bin/temporal
                  arguments:
                    - workflow
                    - start
                    - --type
                    - ${!metadata:workflow_type}
                    - --workflow-id
                    - ${!metadata:workflow_id}
                    - --task-queue
                    - ${!metadata:task_queue}
                    - --input
                    - ${!json:workflow_input}
                    - --namespace
                    - default
                    - --address
                    - ${TEMPORAL_ADDRESS}
      
      # Route to metrics processing
      - check: metadata("route_to") == "metrics"
        output:
          nats_jetstream:
            urls:
              - ${NATS_URL}
            subject: ${!metadata:nats_subject}
            headers:
              Event-Type: ${!metadata:event_type}
              Customer-ID: ${!metadata:customer_id}
              Trace-ID: ${!metadata:trace_id}
            auth:
              nkey_file: ${NATS_CREDS}
      
      # Route to monitoring
      - check: metadata("route_to") == "monitoring"
        output:
          nats_jetstream:
            urls:
              - ${NATS_URL}
            subject: ${!metadata:nats_subject}
            headers:
              Event-Type: ${!metadata:event_type}
              Customer-ID: ${!metadata:customer_id}
            auth:
              nkey_file: ${NATS_CREDS}
      
      # Dead letter queue
      - check: metadata("route_to") == "dlq" || errored()
        output:
          broker:
            pattern: fan_out
            outputs:
              # Store in NATS for inspection
              - nats_jetstream:
                  urls:
                    - ${NATS_URL}
                  subject: dlq.events
                  headers:
                    Original-Subject: ${!metadata:subject}
                    Error-Message: ${!error}
                    Retry-Count: ${!metadata:retry_count}
                    Event-Type: ${!metadata:event_type}
                  auth:
                    nkey_file: ${NATS_CREDS}
              
              # Alert on repeated DLQ entries
              - switch:
                  cases:
                    - check: metadata("retry_count") > 3
                      output:
                        http:
                          url: ${API_URL}/api/v1/alerts
                          verb: POST
                          headers:
                            Authorization: Bearer ${API_TOKEN}
                            Content-Type: application/json
                          timeout: 10s
                          rate_limit: dlq_alerts
                          max_in_flight: 10
                          successful_on: [200, 201, 202]
                          mapping: |
                            root = {
                              "severity": "high",
                              "title": "Event routing failure in DLQ",
                              "description": "Event failed to route after " + metadata("retry_count").string() + " attempts",
                              "details": {
                                "event_type": metadata("event_type"),
                                "customer_id": metadata("customer_id"),
                                "error": error(),
                                "trace_id": metadata("trace_id")
                              },
                              "source": "benthos-event-router",
                              "timestamp": now()
                            }

resources:
  rate_limits:
    dlq_alerts:
      count: 10
      interval: 1m

  caches:
    - label: workflow_dedup
      memory:
        ttl: 300s
        max_items: 10000

metrics:
  prometheus:
    address: 0.0.0.0:4196
    path: /metrics
    namespace: benthos
    subsystem: event_router
  
  mapping: |
    # Track events routed
    counter_events_routed = counter()
    counter_events_routed.incr(1, {
      "event_type": metadata("event_type"),
      "workflow": metadata("workflow_type").or("none"),
      "status": if errored() { "error" } else { "success" }
    })
    
    # Track routing latency
    timer_routing_duration = timing()
    timer_routing_duration.update(metadata("duration_ns"))
    
    # Track DLQ events
    counter_dlq_events = counter()
    counter_dlq_events.incr(if metadata("route_to") == "dlq" { 1 } else { 0 })

logger:
  level: ${LOG_LEVEL:INFO}
  format: json
  static_fields:
    service: benthos-event-router
    version: ${SERVICE_VERSION:1.0.0}

shutdown_timeout: 30s

tracer:
  jaeger:
    agent_address: ${JAEGER_AGENT:localhost:6831}
    service_name: benthos-event-router
    sampler:
      type: probabilistic
      param: 0.1
```

### 13. scripts/eos-wazuh-ccs.sh

```bash
#!/bin/bash
# modules/wazuh-mssp/scripts/eos-wazuh-ccs.sh
# Eos integration script for Wazuh MSSP platform

set -euo pipefail

# Script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MODULE_ROOT="${PROJECT_ROOT}"

# Load configuration
if [[ -f "${PROJECT_ROOT}/.env" ]]; then
    source "${PROJECT_ROOT}/.env"
fi

# Default values
ENVIRONMENT="${ENVIRONMENT:-production}"
TERRAFORM_DIR="${MODULE_ROOT}/terraform"
NOMAD_DIR="${MODULE_ROOT}/nomad"
_DIR="${MODULE_ROOT}/"
TEMPORAL_DIR="${MODULE_ROOT}/temporal"
BENTHOS_DIR="${MODULE_ROOT}/benthos"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*" >&2
}

success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] ✓${NC} $*" >&2
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] ⚠${NC}  $*" >&2
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ✗${NC} $*" >&2
    exit 1
}

# Check dependencies
check_dependencies() {
    local deps=("terraform" "nomad" "consul" "vault" "temporal" "nats-server" "" "jq")
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error "Required dependency '$dep' is not installed"
        fi
    done
    
    success "All dependencies are installed"
}

# Initialize platform infrastructure
init_infrastructure() {
    log "Initializing Wazuh MSSP infrastructure..."
    
    # Change to terraform directory
    cd "${TERRAFORM_DIR}/environments/${ENVIRONMENT}"
    
    # Initialize Terraform
    log "Initializing Terraform..."
    terraform init \
        -backend-config="bucket=${TF_STATE_BUCKET}" \
        -backend-config="key=${ENVIRONMENT}/terraform.tfstate" \
        -backend-config="region=${AWS_REGION}"
    
    # Create terraform plan
    log "Creating Terraform plan..."
    terraform plan \
        -var-file="${ENVIRONMENT}.tfvars" \
        -out=tfplan
    
    # Apply infrastructure
    log "Applying Terraform configuration..."
    terraform apply tfplan
    
    # Get outputs
    local nomad_addr=$(terraform output -raw nomad_server_lb_dns)
    local consul_addr=$(terraform output -raw consul_server_lb_dns)
    local vault_addr=$(terraform output -raw vault_server_lb_dns)
    
    # Export for later use
    export NOMAD_ADDR="http://${nomad_addr}:4646"
    export CONSUL_HTTP_ADDR="http://${consul_addr}:8161"
    export VAULT_ADDR="http://${vault_addr}:8200"
    
    success "Infrastructure initialized"
    
    # Bootstrap services
    bootstrap_services
    
    # Deploy platform services
    deploy_platform_services
}

# Bootstrap Nomad, Consul, and Vault
bootstrap_services() {
    log "Bootstrapping platform services..."
    
    # Bootstrap Vault
    log "Initializing Vault..."
    if ! vault status &>/dev/null; then
        vault operator init -key-shares=5 -key-threshold=3 -format=json > vault-init.json
        
        # Unseal Vault
        for i in {0..2}; do
            local key=$(jq -r ".unseal_keys_b64[$i]" vault-init.json)
            vault operator unseal "$key"
        done
        
        # Login with root token
        export VAULT_TOKEN=$(jq -r '.root_token' vault-init.json)
        
        # Store init data securely
        aws s3 cp vault-init.json "s3://${SECRETS_BUCKET}/vault-init.json" \
            --sse aws:kms --sse-kms-key-id "${KMS_KEY_ID}"
        rm vault-init.json
    fi
    
    # Bootstrap Nomad ACLs
    log "Bootstrapping Nomad ACLs..."
    local nomad_token=$(nomad acl bootstrap -format=json | jq -r '.SecretID')
    export NOMAD_TOKEN="$nomad_token"
    
    # Store in Vault
    vault kv put secret/nomad/bootstrap token="$nomad_token"
    
    # Bootstrap Consul ACLs
    log "Bootstrapping Consul ACLs..."
    local consul_token=$(consul acl bootstrap -format=json | jq -r '.SecretID')
    export CONSUL_HTTP_TOKEN="$consul_token"
    
    # Store in Vault
    vault kv put secret/consul/bootstrap token="$consul_token"
    
    success "Services bootstrapped"
}

# Deploy platform services
deploy_platform_services() {
    log "Deploying platform services..."
    
    # Create namespaces
    log "Creating Nomad namespaces..."
    nomad namespace apply -description "Platform services" platform
    nomad namespace apply -description "Temporal workflows" temporal
    
    # Apply Nomad policies
    log "Applying Nomad policies..."
    for policy in "${NOMAD_DIR}/policies"/*.hcl; do
        nomad acl policy apply -description "$(basename "$policy" .hcl) policy" \
            "$(basename "$policy" .hcl)" "$policy"
    done
    
    # Deploy core jobs
    log "Deploying core platform jobs..."
    local jobs=(
        "temporal-server"
        "nats-cluster"
        "postgres"
        "traefik"
        "prometheus"
        "grafana"
    )
    
    for job in "${jobs[@]}"; do
        log "Deploying ${job}..."
        nomad job run "${NOMAD_DIR}/jobs/core/${job}.nomad"
    done
    
    # Wait for services to be healthy
    log "Waiting for services to become healthy..."
    for job in "${jobs[@]}"; do
        wait_for_job_healthy "$job" "platform"
    done
    
    # Deploy platform jobs
    log "Deploying platform application jobs..."
    nomad job run "${NOMAD_DIR}/jobs/api-service.nomad"
    nomad job run "${NOMAD_DIR}/jobs/temporal-workers.nomad"
    nomad job run "${NOMAD_DIR}/jobs/benthos-pipelines.nomad"
    
    success "Platform services deployed"
}

# Wait for a Nomad job to be healthy
wait_for_job_healthy() {
    local job_name="$1"
    local namespace="${2:-default}"
    local timeout=300
    local elapsed=0
    
    while [[ $elapsed -lt $timeout ]]; do
        local status=$(nomad job status -namespace="$namespace" "$job_name" -json | \
            jq -r '.Allocations[0].ClientStatus // "pending"')
        
        if [[ "$status" == "running" ]]; then
            return 0
        fi
        
        sleep 5
        elapsed=$((elapsed + 5))
    done
    
    error "Job $job_name failed to become healthy within ${timeout}s"
}

# Add a new customer
add_customer() {
    local config_file="${1:-}"
    
    if [[ -z "$config_file" || ! -f "$config_file" ]]; then
        error "Configuration file required: eos create wazuh-ccs --add-customer <config.json>"
    fi
    
    log "Adding customer from configuration: $config_file"
    
    # Validate configuration
    if ! jq empty "$config_file" 2>/dev/null; then
        error "Invalid JSON configuration file"
    fi
    
    # Extract customer information
    local customer_id=$(jq -r '.customer_id' "$config_file")
    local company_name=$(jq -r '.company_name' "$config_file")
    local tier=$(jq -r '.tier // "starter"' "$config_file")
    
    log "Customer: ${company_name} (${customer_id}) - Tier: ${tier}"
    
    # Create Nomad namespace for customer
    log "Creating customer namespace..."
    nomad namespace apply \
        -description "Customer: ${company_name}" \
        -meta "customer_id=${customer_id}" \
        -meta "tier=${tier}" \
        "customer-${customer_id}"
    
    # Apply resource quota based on tier
    log "Applying resource quota..."
    case "$tier" in
        starter)
            cpu_limit=4000
            memory_limit=8192
            ;;
        pro)
            cpu_limit=8000
            memory_limit=16384
            ;;
        enterprise)
            cpu_limit=16000
            memory_limit=32768
            ;;
        *)
            error "Unknown tier: ${tier}"
            ;;
    esac
    
    nomad quota apply \
        -namespace "customer-${customer_id}" \
        -region global \
        -cpu-limit "$cpu_limit" \
        -memory-limit "$memory_limit" \
        "customer-${customer_id}"
    
    # Create NATS account
    log "Creating NATS account..."
    create_nats_account "$customer_id" "$tier"
    
    # Store customer configuration in Vault
    log "Storing customer configuration..."
    vault kv put "secret/customers/${customer_id}/config" @"$config_file"
    
    # Generate secrets for customer
    log "Generating customer secrets..."
    generate_customer_secrets "$customer_id"
    
    # Trigger provisioning workflow
    log "Triggering provisioning workflow..."
    temporal workflow start \
        --task-queue provisioning \
        --type CustomerProvisioningWorkflow \
        --workflow-id "provision-${customer_id}" \
        --input-file "$config_file" \
        --namespace default \
        --address "${TEMPORAL_ADDRESS:-localhost:7233}"
    
    success "Customer provisioning initiated"
    log "Workflow ID: provision-${customer_id}"
    log "Monitor progress: temporal workflow show -w provision-${customer_id}"
}

# Create NATS account for customer
create_nats_account() {
    local customer_id="$1"
    local tier="$2"
    
    # Set limits based on tier
    case "$tier" in
        starter)
            mem_limit="1GB"
            disk_limit="10GB"
            max_streams=10
            max_consumers=100
            ;;
        pro)
            mem_limit="5GB"
            disk_limit="50GB"
            max_streams=50
            max_consumers=500
            ;;
        enterprise)
            mem_limit="20GB"
            disk_limit="200GB"
            max_streams=200
            max_consumers=2000
            ;;
    esac
    
    # Create account using nsc
    export NSC_HOME="${NSC_HOME:-/var/lib/nats/.nsc}"
    
    nsc add account "CUSTOMER-${customer_id^^}" \
        --js-mem-storage "$mem_limit" \
        --js-disk-storage "$disk_limit" \
        --js-streams "$max_streams" \
        --js-consumer "$max_consumers"
    
    # Generate user credentials
    nsc add user "${customer_id}-service" -a "CUSTOMER-${customer_id^^}"
    
    # Export credentials
    local creds=$(nsc generate creds -a "CUSTOMER-${customer_id^^}" -n "${customer_id}-service")
    
    # Store in Vault
    vault kv put "secret/customers/${customer_id}/nats" creds="$creds"
}

# Generate secrets for customer
generate_customer_secrets() {
    local customer_id="$1"
    
    # Generate various secrets
    local secrets=(
        "wazuh_api_password=$(openssl rand -base64 32)"
        "wazuh_cluster_key=$(openssl rand -base64 32)"
        "indexer_admin_password=$(openssl rand -base64 24)"
        "kibanaserver_password=$(openssl rand -base64 24)"
        "agent_enrollment_password=$(openssl rand -base64 16)"
        "dashboard_admin_password=$(openssl rand -base64 24)"
    )
    
    # Store each secret in Vault
    for secret in "${secrets[@]}"; do
        local key="${secret%%=*}"
        local value="${secret#*=}"
        vault kv put "secret/customers/${customer_id}/wazuh/${key}" value="$value"
    done
    
    # Generate SSL certificates
    log "Generating SSL certificates..."
    generate_customer_certificates "$customer_id"
}

# Generate SSL certificates for customer
generate_customer_certificates() {
    local customer_id="$1"
    
    # Create temporary directory
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Generate CA if not exists
    if ! vault read pki/cert/ca &>/dev/null; then
        vault secrets enable pki
        vault secrets tune -max-lease-ttl=87600h pki
        
        vault write -field=certificate pki/root/generate/internal \
            common_name="Wazuh MSSP CA" \
            ttl=87600h > ca.crt
    fi
    
    # Generate certificates for customer
    local nodes=("indexer" "server" "dashboard")
    
    for node in "${nodes[@]}"; do
        vault write pki/issue/wazuh-${node} \
            common_name="wazuh-${node}-${customer_id}.service.consul" \
            alt_names="localhost,${node}.${customer_id}.local" \
            ttl=8760h \
            format=pem > "${node}.json"
        
        # Extract and store certificates
        jq -r '.data.certificate' "${node}.json" > "${node}.crt"
        jq -r '.data.private_key' "${node}.json" > "${node}.key"
        jq -r '.data.ca_chain[]' "${node}.json" > "ca.crt"
        
        # Store in Vault
        vault kv put "secret/customers/${customer_id}/certificates/${node}" \
            certificate="$(cat ${node}.crt)" \
            private_key="$(cat ${node}.key)" \
            ca_certificate="$(cat ca.crt)"
    done
    
    # Cleanup
    cd - &>/dev/null
    rm -rf "$temp_dir"
}

# Scale customer resources
scale_customer() {
    local customer_id="${1:-}"
    local new_tier="${2:-}"
    
    if [[ -z "$customer_id" || -z "$new_tier" ]]; then
        error "Usage: eos create wazuh-ccs --scale-customer <customer_id> <tier>"
    fi
    
    log "Scaling customer ${customer_id} to tier: ${new_tier}"
    
    # Validate tier
    if [[ ! "$new_tier" =~ ^(starter|pro|enterprise)$ ]]; then
        error "Invalid tier. Must be: starter, pro, or enterprise"
    fi
    
    # Get current configuration
    local current_config=$(vault kv get -format=json "secret/customers/${customer_id}/config" | jq -r '.data.data')
    
    if [[ -z "$current_config" ]]; then
        error "Customer ${customer_id} not found"
    fi
    
    local current_tier=$(echo "$current_config" | jq -r '.tier')
    
    if [[ "$current_tier" == "$new_tier" ]]; then
        warn "Customer is already on ${new_tier} tier"
        return 0
    fi
    
    # Create scaling request
    local scaling_request=$(cat <<EOF
{
  "customer_id": "${customer_id}",
  "current_tier": "${current_tier}",
  "requested_tier": "${new_tier}",
  "requested_by": "${USER}",
  "requested_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
)
    
    # Store scaling request
    echo "$scaling_request" > "/tmp/scale-${customer_id}.json"
    
    # Trigger scaling workflow
    log "Triggering scaling workflow..."
    temporal workflow start \
        --task-queue operations \
        --type CustomerScalingWorkflow \
        --workflow-id "scale-${customer_id}-$(date +%s)" \
        --input-file "/tmp/scale-${customer_id}.json" \
        --namespace default \
        --address "${TEMPORAL_ADDRESS:-localhost:7233}"
    
    # Cleanup
    rm -f "/tmp/scale-${customer_id}.json"
    
    success "Customer scaling initiated"
}

# Remove customer
remove_customer() {
    local customer_id="${1:-}"
    
    if [[ -z "$customer_id" ]]; then
        error "Usage: eos create wazuh-ccs --remove-customer <customer_id>"
    fi
    
    # Confirm removal
    warn "This will permanently remove customer ${customer_id} and all associated data"
    read -p "Are you sure? Type 'yes' to confirm: " confirmation
    
    if [[ "$confirmation" != "yes" ]]; then
        log "Removal cancelled"
        return 0
    fi
    
    log "Removing customer ${customer_id}..."
    
    # Create removal request
    local removal_request=$(cat <<EOF
{
  "customer_id": "${customer_id}",
  "remove_data": true,
  "backup_before_remove": true,
  "requested_by": "${USER}",
  "requested_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
)
    
    # Trigger removal workflow
    log "Triggering removal workflow..."
    temporal workflow start \
        --task-queue operations \
        --type CustomerRemovalWorkflow \
        --workflow-id "remove-${customer_id}-$(date +%s)" \
        --input "$removal_request" \
        --namespace default \
        --address "${TEMPORAL_ADDRESS:-localhost:7233}"
    
    success "Customer removal initiated"
}

# Backup customer data
backup_customer() {
    local customer_id="${1:-}"
    local backup_type="${2:-incremental}"
    
    if [[ -z "$customer_id" ]]; then
        error "Usage: eos create wazuh-ccs --backup-customer <customer_id> [full|incremental]"
    fi
    
    log "Creating ${backup_type} backup for customer ${customer_id}..."
    
    # Create backup request
    local backup_request=$(cat <<EOF
{
  "customer_id": "${customer_id}",
  "backup_type": "${backup_type}",
  "requested_by": "${USER}",
  "requested_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
)
    
    # Trigger backup workflow
    log "Triggering backup workflow..."
    temporal workflow start \
        --task-queue operations \
        --type BackupWorkflow \
        --workflow-id "backup-${customer_id}-$(date +%s)" \
        --input "$backup_request" \
        --namespace default \
        --address "${TEMPORAL_ADDRESS:-localhost:7233}"
    
    success "Backup initiated"
}

# Show platform or customer status
show_status() {
    local customer_id="${1:-}"
    
    if [[ -z "$customer_id" ]]; then
        # Show platform status
        log "Platform Status"
        echo "================"
        
        # Nomad status
        echo -e "\n${BLUE}Nomad Cluster:${NC}"
        nomad server members
        
        echo -e "\n${BLUE}Nomad Jobs:${NC}"
        nomad job status -namespace=platform
        
        # Consul status
        echo -e "\n${BLUE}Consul Services:${NC}"
        consul catalog services
        
        # Temporal status
        echo -e "\n${BLUE}Temporal Status:${NC}"
        temporal operator cluster system
        
        # Customer count
        echo -e "\n${BLUE}Customers:${NC}"
        nomad namespace list | grep -c "customer-" || echo "0"
        
    else
        # Show customer status
        log "Customer Status: ${customer_id}"
        echo "=========================="
        
        # Check if customer exists
        if ! nomad namespace status "customer-${customer_id}" &>/dev/null; then
            error "Customer ${customer_id} not found"
        fi
        
        # Customer configuration
        echo -e "\n${BLUE}Configuration:${NC}"
        vault kv get -format=json "secret/customers/${customer_id}/config" | \
            jq -r '.data.data | {customer_id, company_name, tier, subdomain}'
        
        # Nomad jobs
        echo -e "\n${BLUE}Deployments:${NC}"
        nomad job status -namespace="customer-${customer_id}"
        
        # Service health
        echo -e "\n${BLUE}Service Health:${NC}"
        local services=("wazuh-indexer" "wazuh-server" "wazuh-dashboard")
        for service in "${services[@]}"; do
            local status=$(consul health state "${service}-${customer_id}" | jq -r '.[0].Status // "unknown"')
            case "$status" in
                passing) echo -e "${service}: ${GREEN}✓ healthy${NC}" ;;
                warning) echo -e "${service}: ${YELLOW}⚠ warning${NC}" ;;
                critical) echo -e "${service}: ${RED}✗ critical${NC}" ;;
                *) echo -e "${service}: unknown" ;;
            esac
        done
        
        # Resource usage
        echo -e "\n${BLUE}Resource Usage:${NC}"
        nomad quota status "customer-${customer_id}" 2>/dev/null || echo "No quota information available"
        
        # Recent workflows
        echo -e "\n${BLUE}Recent Workflows:${NC}"
        temporal workflow list \
            --query "WorkflowId STARTS_WITH '${customer_id}'" \
            --limit 5 \
            --fields WorkflowId,Type,Status,StartTime
    fi
}

# Restore customer from backup
restore_customer() {
    local customer_id="${1:-}"
    local backup_id="${2:-}"
    
    if [[ -z "$customer_id" || -z "$backup_id" ]]; then
        error "Usage: eos create wazuh-ccs --restore-customer <customer_id> <backup_id>"
    fi
    
    log "Restoring customer ${customer_id} from backup ${backup_id}..."
    
    # Create restore request
    local restore_request=$(cat <<EOF
{
  "customer_id": "${customer_id}",
  "backup_id": "${backup_id}",
  "restore_type": "full",
  "requested_by": "${USER}",
  "requested_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
)
    
    # Trigger restore workflow
    log "Triggering restore workflow..."
    temporal workflow start \
        --task-queue operations \
        --type RestoreWorkflow \
        --workflow-id "restore-${customer_id}-$(date +%s)" \
        --input "$restore_request" \
        --namespace default \
        --address "${TEMPORAL_ADDRESS:-localhost:7233}"
    
    success "Restore initiated"
}

# Generate customer report
generate_report() {
    local customer_id="${1:-}"
    local report_type="${2:-summary}"
    local output_file="${3:-report.pdf}"
    
    if [[ -z "$customer_id" ]]; then
        error "Usage: eos create wazuh-ccs --report <customer_id> [summary|detailed|compliance] [output_file]"
    fi
    
    log "Generating ${report_type} report for customer ${customer_id}..."
    
    # Create report request
    local report_request=$(cat <<EOF
{
  "customer_id": "${customer_id}",
  "report_type": "${report_type}",
  "output_format": "pdf",
  "requested_by": "${USER}",
  "requested_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
)
    
    # Call API to generate report
    curl -X POST \
        -H "Authorization: Bearer ${API_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$report_request" \
        "${API_URL}/api/v1/customers/${customer_id}/reports" \
        -o "$output_file"
    
    if [[ $? -eq 0 ]]; then
        success "Report generated: ${output_file}"
    else
        error "Failed to generate report"
    fi
}

# Main command handler
main() {
    local command="${1:-}"
    shift || true
    
    case "$command" in
        --init)
            check_dependencies
            init_infrastructure
            ;;
        --add-customer)
            add_customer "$@"
            ;;
        --scale-customer)
            scale_customer "$@"
            ;;
        --remove-customer)
            remove_customer "$@"
            ;;
        --backup-customer)
            backup_customer "$@"
            ;;
        --restore-customer)
            restore_customer "$@"
            ;;
        --status)
            show_status "$@"
            ;;
        --report)
            generate_report "$@"
            ;;
        --help|-h|"")
            cat <<EOF
Wazuh MSSP Platform Management

Usage: eos create wazuh-ccs <command> [options]

Commands:
  --init                          Initialize MSSP infrastructure
  --add-customer <config.json>    Add new customer from config file
  --scale-customer <id> <tier>    Change customer tier (starter/pro/enterprise)
  --remove-customer <id>          Remove customer (requires confirmation)
  --backup-customer <id> [type]   Create backup (full/incremental)
  --restore-customer <id> <backup> Restore customer from backup
  --status [customer_id]          Show platform or customer status
  --report <id> [type] [output]   Generate customer report

Configuration File Format:
{
  "customer_id": "cust_12345",
  "company_name": "ACME Corporation",
  "subdomain": "acme",
  "tier": "pro",
  "admin_email": "admin@acme.com",
  "admin_name": "John Doe",
  "authentik_data": {
    "group_id": "group_12345",
    "user_id": "user_67890"
  }
}

Examples:
  # Initialize the platform
  eos create wazuh-ccs --init

  # Add a new customer
  eos create wazuh-ccs --add-customer customer.json

  # Scale customer to enterprise tier
  eos create wazuh-ccs --scale-customer cust_12345 enterprise

  # Check customer status
  eos create wazuh-ccs --status cust_12345

  # Create a backup
  eos create wazuh-ccs --backup-customer cust_12345 full

Environment Variables:
  ENVIRONMENT          Deployment environment (dev/staging/production)
  NOMAD_ADDR          Nomad server address
  CONSUL_HTTP_ADDR    Consul server address
  VAULT_ADDR          Vault server address
  TEMPORAL_ADDRESS    Temporal server address
  API_URL             Platform API URL

For more information, see the documentation at:
https://docs.wazuh-mssp.com
EOF
            ;;
        *)
            error "Unknown command: ${command}. Use --help for usage information."
            ;;
    esac
}

# Run main function
main "$@"