# Eos Terraform Integration

Eos provides comprehensive Terraform integration for infrastructure automation and deployment. This allows you to use familiar tools (Caddy, Nginx) with modern orchestration (K3s) and infrastructure as code (Terraform).

## 🚀 Quick Start

```bash
# Install Terraform via eos
eos create terraform

# Deploy K3s cluster with Caddy + Nginx (replaces Traefik)
eos create k3s-caddy-nginx --domain mail.example.com --enable-mail

# For cloud deployment
eos create k3s-caddy-nginx --domain mail.example.com --cloud --enable-mail
```

## 📦 Available Commands

### HashiCorp Tools Installation
```bash
# Install individual tools
eos create terraform
eos create vault  
eos create consul
eos create nomad
eos create packer

# Install all HashiCorp tools
eos create hcl all

# Alternative syntax
eos create hcl terraform
eos create hcl vault
```

### Infrastructure Templates

#### K3s with Caddy + Nginx (Recommended)
```bash
# Basic cluster
eos create k3s-caddy-nginx --domain example.com

# With mail server support
eos create k3s-caddy-nginx --domain mail.example.com --enable-mail

# Cloud deployment (Hetzner)
eos create k3s-caddy-nginx \
  --domain mail.example.com \
  --cloud \
  --enable-mail \
  --cluster-name production-mail \
  --server-type cx21 \
  --location nbg1
```

#### Traditional K3s with Terraform
```bash
# Generate K3s infrastructure on cloud
eos create k3s-terraform --provider hetzner --server-type cx21

# With existing K3s command
eos create k3s --terraform
```

#### Hecate Mail Server
```bash
# Complete mail server stack
eos create hecate-terraform --domain mail.example.com --cloud

# Local deployment
eos create hecate-terraform --domain mail.example.com
```

### Terraform Workflow Commands
```bash
# Individual operations
eos create terraform-plan [directory]
eos create terraform-apply [directory] 
eos create terraform-destroy [directory]
eos create terraform-init [directory]
eos create terraform-validate [directory]
eos create terraform-fmt [directory]

# Full workflow (init → validate → plan → apply)
eos create terraform-deploy [directory]

# With auto-approval
eos create terraform-apply --auto-approve [directory]
eos create terraform-deploy --auto-approve [directory]
```

## 🏗️ Architecture Overview

### K3s + Caddy + Nginx Stack

```
┌─────────────────┐    ┌─────────────────┐
│   Internet      │    │   Your Domain   │
│   Traffic       │────│  mail.com       │
└─────────────────┘    └─────────────────┘
          │                       │
          ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│  Load Balancer  │    │   DNS/Firewall  │
│   (MetalLB)     │    │    (Hetzner)    │
└─────────────────┘    └─────────────────┘
          │
          ▼
┌─────────────────────────────────────────────┐
│              K3s Cluster                    │
│  ┌─────────────┐    ┌─────────────────────┐ │
│  │    Caddy    │    │      Nginx          │ │
│  │   HTTP/S    │    │   Mail Proxy        │ │
│  │  Port 80/443│    │   SMTP/IMAP/POP3    │ │
│  └─────────────┘    └─────────────────────┘ │
│           │                    │            │
│           ▼                    ▼            │
│  ┌─────────────┐    ┌─────────────────────┐ │
│  │   Your      │    │     Mail Server     │ │
│  │   Apps      │    │    (Stalwart)       │ │
│  └─────────────┘    └─────────────────────┘ │
└─────────────────────────────────────────────┘
```

**Key Components:**
- **Caddy**: HTTP/HTTPS reverse proxy with automatic SSL (replaces Traefik)
- **Nginx**: Mail protocol proxy (SMTP/IMAP/POP3/Sieve)
- **K3s**: Lightweight Kubernetes without Traefik
- **MetalLB**: LoadBalancer services for K3s
- **Stalwart**: Modern mail server (optional)

## 🎯 Use Cases

### 1. Mail Server Deployment
Perfect for deploying production mail servers with familiar reverse proxy tools:

```bash
# Complete mail server on Hetzner Cloud
eos create k3s-caddy-nginx \
  --domain mail.cybermonkey.net.au \
  --cloud \
  --enable-mail \
  --cluster-name cybermonkey-mail

cd k3s-caddy-nginx
export HCLOUD_TOKEN='your-hetzner-token'
./deploy.sh
```

**What you get:**
- K3s cluster on Hetzner Cloud
- Caddy handling HTTP/HTTPS with Let's Encrypt
- Nginx proxying all mail protocols
- Firewall rules for mail ports
- Ready for Stalwart or other mail servers

### 2. Web Application Hosting
Deploy web applications with Caddy instead of learning Traefik:

```bash
eos create k3s-caddy-nginx --domain apps.example.com --cloud
cd k3s-caddy-nginx
# Edit config/Caddyfile.tpl to add your app routes
terraform apply
```

### 3. Hybrid Infrastructure
Use both direct installation and Terraform deployment:

```bash
# Direct K3s installation for development
eos create k3s

# Terraform-managed K3s for production
eos create k3s-terraform --provider hetzner
```

## 📂 Generated File Structure

### K3s + Caddy + Nginx
```
k3s-caddy-nginx/
├── main.tf                    # Main Terraform configuration
├── terraform.tfvars          # Variables file
├── k3s-cloud-init.yaml      # Cloud-init script (if --cloud)
├── deploy.sh                 # Deployment script
└── config/
    ├── Caddyfile.tpl         # Caddy configuration template
    └── nginx-mail.conf.tpl   # Nginx mail proxy config (if --enable-mail)
```

### Traditional Infrastructure
```
terraform-k3s/
├── main.tf                   # Infrastructure definition
├── k3s-cloud-init.yaml      # K3s installation script
├── terraform.tfvars         # Configuration variables
└── README.md                # Setup instructions
```

## 🔧 Configuration Examples

### Caddyfile Template
```caddyfile
# Automatic HTTPS for your domain
example.com {
    # Health check
    handle /health {
        respond "OK" 200
    }
    
    # Proxy to your K8s services
    reverse_proxy /api/* {
        to http://api-service.default.svc.cluster.local:80
    }
    
    reverse_proxy /* {
        to http://frontend-service.default.svc.cluster.local:80
    }
    
    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options "nosniff"
        -Server
    }
}
```

### Nginx Mail Proxy
```nginx
mail {
    server_name mail.example.com;
    auth_http http://stalwart-mail.default.svc.cluster.local:8080/auth;
    
    # SMTP
    server {
        listen 25;
        protocol smtp;
        smtp_auth login plain;
    }
    
    # IMAPS
    server {
        listen 993 ssl;
        protocol imap;
        ssl_certificate /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;
    }
    
    # Additional mail protocols...
}
```

## 🚢 Deployment Workflows

### Development to Production Pipeline

1. **Development** (Local K3s)
```bash
eos create k3s
# Test your applications locally
```

2. **Staging** (Single cloud instance)
```bash
eos create k3s-caddy-nginx --domain staging.example.com --cloud
```

3. **Production** (Multi-node with mail)
```bash
eos create k3s-caddy-nginx \
  --domain example.com \
  --cloud \
  --enable-mail \
  --cluster-name production
```

### Iterative Deployment
```bash
# Make changes to configuration
vim config/Caddyfile.tpl

# Plan changes
eos create terraform-plan .

# Apply changes
eos create terraform-apply .

# Or use the full workflow
eos create terraform-deploy .
```

## 💡 Why This Approach?

### Advantages over Default Traefik Ingress

1. **Familiar Tools**: Use Caddy + Nginx instead of learning Traefik
2. **Automatic SSL**: Caddy handles Let's Encrypt automatically
3. **Mail Protocol Support**: Nginx excels at mail proxy (SMTP/IMAP/POP3)
4. **Simpler Configuration**: Plain text config files vs. complex YAML
5. **Better Observability**: Standard access logs and metrics
6. **Production Ready**: Battle-tested reverse proxy solutions

### Infrastructure as Code Benefits

1. **Reproducible**: Deploy identical environments every time
2. **Version Controlled**: Track infrastructure changes in Git
3. **Collaborative**: Team can review infrastructure changes
4. **Rollback Capable**: Revert to previous working configurations
5. **Documentation**: Infrastructure configuration is self-documenting

## 🔍 Troubleshooting

### Common Issues

**Terraform not found:**
```bash
eos create terraform
# or
eos create hcl terraform
```

**Cloud deployment fails:**
```bash
# Ensure token is set
export HCLOUD_TOKEN='your-token'

# Verify SSH key exists in Hetzner Cloud
# Update terraform.tfvars with correct ssh_key_name
```

**Services not accessible:**
```bash
# Check LoadBalancer status
kubectl get svc -n ingress-system

# Check pod status  
kubectl get pods -n ingress-system

# View logs
kubectl logs -n ingress-system deployment/caddy-ingress
kubectl logs -n ingress-system deployment/nginx-mail-proxy
```

### Useful Commands

```bash
# Get cluster info
kubectl cluster-info

# Check ingress services
kubectl get svc -n ingress-system

# View configurations
kubectl get configmap -n ingress-system

# Port forward for testing
kubectl port-forward -n ingress-system svc/caddy-ingress 8080:80

# Get external IPs
terraform output
```

## 🔮 Future Enhancements

- AWS/Azure cloud provider support
- Multi-node K3s clusters
- Integrated monitoring (Prometheus/Grafana)
- Database deployment templates
- CI/CD pipeline integration
- Backup automation

## 📚 Related Documentation

- [K3s Documentation](https://docs.k3s.io/)
- [Caddy Documentation](https://caddyserver.com/docs/)
- [Nginx Mail Proxy](http://nginx.org/en/docs/mail/ngx_mail_core_module.html)
- [Terraform Documentation](https://www.terraform.io/docs/)
- [Hetzner Cloud API](https://docs.hetzner.cloud/)

---

*This integration replaces complex Traefik ingress setups with familiar, production-ready tools while maintaining the power and flexibility of K3s and Terraform.*