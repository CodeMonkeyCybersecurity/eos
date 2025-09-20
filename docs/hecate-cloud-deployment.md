# Hecate Cloud Deployment Guide

*Last Updated: 2025-01-20*

## Overview

Hecate is designed to be deployed exclusively on cloud infrastructure with a public IP address. This guide covers deployment on major cloud providers and DNS configuration for automatic HTTPS.

## Requirements

### Infrastructure Requirements
- **Public IP Address**: Required for Caddy's automatic HTTPS
- **Open Ports**: 80, 443 (HTTP/HTTPS), 2019 (Caddy Admin)
- **Minimum Resources**: 2 vCPUs, 4GB RAM, 20GB storage
- **Operating System**: Ubuntu 22.04 LTS or newer

### DNS Requirements
- A domain name pointed to your server's public IP
- Access to DNS provider API for automatic certificate renewal

## Supported Cloud Providers

### Hetzner Cloud
```bash
# Create a cloud server
hcloud server create \
  --name hecate-prod \
  --type cx21 \
  --image ubuntu-22.04 \
  --ssh-key your-key \
  --location fsn1

# Get the public IP
hcloud server ip hecate-prod
```

### AWS EC2
```bash
# Launch instance with public IP
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t3.medium \
  --key-name your-key \
  --security-group-ids sg-hecate \
  --associate-public-ip-address
```

### DigitalOcean
```bash
# Create droplet
doctl compute droplet create hecate-prod \
  --size s-2vcpu-4gb \
  --image ubuntu-22-04-x64 \
  --region nyc3 \
  --ssh-keys your-key-id
```

### Google Cloud Platform
```bash
# Create VM instance
gcloud compute instances create hecate-prod \
  --machine-type=e2-medium \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud \
  --zone=us-central1-a
```

### Azure
```bash
# Create VM
az vm create \
  --resource-group hecate-rg \
  --name hecate-prod \
  --image UbuntuLTS \
  --size Standard_B2s \
  --public-ip-address hecate-ip
```

## Initial Server Setup

1. **Connect to your server**:
   ```bash
   ssh root@YOUR_PUBLIC_IP
   ```

2. **Update system**:
   ```bash
   apt update && apt upgrade -y
   ```

3. **Install Eos**:
   ```bash
   curl -fsSL https://github.com/CodeMonkeyCybersecurity/eos/releases/latest/download/install.sh | bash
   ```

## Configure DNS Challenge

Hecate uses Caddy's DNS challenge for automatic HTTPS certificates. This is required for cloud deployments.

### 1. Set DNS Provider in 

Create `/srv//hecate.sls`:

```yaml
hecate:
  # Your domain
  default_domain: hecate.example.com
  admin_email: admin@example.com
  
  # DNS provider for ACME challenges
  dns_provider: cloudflare  # or: hetzner, route53, digitalocean
  
  # DNS API credentials (choose one based on provider)
  dns_credentials:
    # For Cloudflare
    cloudflare_api_token: "your-cloudflare-api-token"
    
    # For Hetzner
    hetzner_api_token: "your-hetzner-api-token"
    
    # For Route53
    aws_access_key_id: "your-aws-key"
    aws_secret_access_key: "your-aws-secret"
    
    # For DigitalOcean
    digitalocean_token: "your-do-token"
```

### 2. Configure DNS Records

Point your domain to the server's public IP:

```
Type  Name     Value
A     hecate   YOUR_PUBLIC_IP
A     *.hecate YOUR_PUBLIC_IP
```

## Deploy Hecate

1. **Bootstrap the system**:
   ```bash
   eos bootstrap
   ```

2. **Deploy Hecate**:
   ```bash
   eos create hecate
   ```

The deployment will:
- Detect you're on a cloud server with public IP
- Configure Caddy with DNS challenge for HTTPS
- Set up all Hecate components

## Post-Deployment

### Verify Deployment
```bash
# Check services
eos list services

# Check Caddy status
curl http://localhost:2019/config/

# Test HTTPS
curl https://hecate.example.com/health
```

### Access Interfaces
- **Hecate UI**: https://hecate.example.com
- **Authentik**: https://auth.hecate.example.com
- **Admin Password**: Run `eos read hecate admin-password`

### Add Routes
```bash
# Add a service route
eos create hecate route \
  --domain app.example.com \
  --upstream http://10.0.0.5:8080 \
  --auth-required
```

## Security Considerations

### Firewall Rules
Ensure only required ports are open:

```bash
# UFW example
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw allow 2019/tcp  # Caddy Admin (localhost only)
ufw enable
```

### SSL/TLS Configuration
- Caddy automatically obtains and renews certificates
- HSTS is enabled by default
- TLS 1.2 and 1.3 only

### Monitoring
```bash
# View Caddy logs
nomad logs -f hecate-caddy

# Check certificate status
curl http://localhost:2019/pki/ca/certificates
```

## Troubleshooting

### NAT Detection Error
If you see "Server is behind NAT", ensure:
- Server has a public IP assigned
- No NAT gateway between server and internet
- Security groups allow inbound 80/443

### DNS Challenge Failures
- Verify DNS API credentials
- Check DNS propagation: `dig hecate.example.com`
- Review Caddy logs for ACME errors

### Certificate Issues
```bash
# Force certificate renewal
curl -X POST http://localhost:2019/pki/ca/renew

# Check ACME account
curl http://localhost:2019/pki/ca/acme
```

## Maintenance

### Backup Secrets
```bash
# Backup all secrets
eos backup hecate secrets

# Backup configuration
eos backup hecate config
```

### Update Hecate
```bash
# Update to latest version
eos update hecate
```

### Scale Services
```bash
# Add more Authentik workers
eos update hecate scale authentik-worker 3
```

## Support

For issues or questions:
- GitHub Issues: https://github.com/CodeMonkeyCybersecurity/eos/issues
- Documentation: https://wiki.cybermonkey.net.au
- Email: main@cybermonkey.net.au