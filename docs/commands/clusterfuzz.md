# ClusterFuzz Deployment Guide

The `eos create clusterfuzz` command deploys Google's ClusterFuzz fuzzing infrastructure on HashiCorp Nomad, providing a scalable solution for continuous security testing.

## Overview

ClusterFuzz is Google's scalable fuzzing infrastructure that has found thousands of bugs in Chrome, Android, and other projects. This command adapts ClusterFuzz for local deployment on Nomad with MinIO storage, PostgreSQL database, and Redis queuing.

## Quick Start

```bash
# Deploy with default settings (MinIO + PostgreSQL + Redis)
eos create clusterfuzz

# Deploy with custom configuration
eos create clusterfuzz \
  --bot-count 5 \
  --preemptible-bot-count 10 \
  --domain "fuzzing.local" \
  --storage-backend minio \
  --s3-access-key "admin" \
  --s3-secret-key "supersecret"
```

## Prerequisites

- **Nomad cluster** running and accessible
- **Docker** installed on Nomad nodes
- **PostgreSQL client** (for database initialization)
- **curl** (for health checks)

## Configuration Options

### Storage Backends

#### MinIO (Default)
```bash
eos create clusterfuzz --storage-backend minio \
  --s3-endpoint "http://localhost:9000" \
  --s3-access-key "admin" \
  --s3-secret-key "password123"
```

#### External S3
```bash
eos create clusterfuzz --storage-backend s3 \
  --s3-endpoint "https://s3.amazonaws.com" \
  --s3-access-key "AKIA..." \
  --s3-secret-key "..." \
  --s3-bucket "my-clusterfuzz-bucket"
```

### Database Backends

#### PostgreSQL (Default)
```bash
eos create clusterfuzz --database-backend postgresql
```

#### MongoDB
```bash
eos create clusterfuzz --database-backend mongodb
```

### Queue Backends

#### Redis (Default)
```bash
eos create clusterfuzz --queue-backend redis
```

#### RabbitMQ
```bash
eos create clusterfuzz --queue-backend rabbitmq
```

### Vault Integration

Store secrets securely in HashiCorp Vault:
```bash
eos create clusterfuzz --use-vault \
  --vault-path "secret/clusterfuzz"
```

## Deployment Architecture

The deployment creates the following components:

### Core Services (`clusterfuzz-core` job)
- **Database**: PostgreSQL or MongoDB for metadata storage
- **Queue**: Redis or RabbitMQ for task coordination  
- **Storage**: MinIO for artifact storage
- **Web Interface**: ClusterFuzz web UI on port 8080

### Fuzzing Bots (`clusterfuzz-bots` job)
- **Regular Bots**: Handle all task types (default: 3)
- **Preemptible Bots**: Fuzzing-only, can be interrupted (default: 5)

## Network Ports

| Service | Port | Purpose |
|---------|------|---------|
| Web UI | 8080 | ClusterFuzz web interface |
| PostgreSQL | 5432 | Database connections |
| Redis | 6379 | Queue operations |
| MinIO | 9000 | Object storage API |
| MinIO Console | 9001 | MinIO web interface |

## Post-Deployment

### Access URLs
- **ClusterFuzz Web UI**: `http://clusterfuzz.local:8080`
- **MinIO Console**: `http://clusterfuzz.local:9001`

### Initial Setup
1. **Access the web interface** to configure fuzzing jobs
2. **Upload fuzzing targets** (binaries, source code)
3. **Configure job parameters** (fuzzing engines, timeouts)
4. **Monitor fuzzing progress** and crash reports

### Example Fuzzing Job
```bash
# Upload a binary to fuzz
curl -X POST http://clusterfuzz.local:8080/upload \
  -F "binary=@/path/to/target" \
  -F "job_type=libfuzzer" \
  -F "platform=linux"
```

## Monitoring and Management

### Check Deployment Status
```bash
# Check job status
nomad job status clusterfuzz-core
nomad job status clusterfuzz-bots

# View logs
nomad alloc logs <allocation-id>

# Scale bots
nomad job scale clusterfuzz-bots regular-bots 10
```

### Storage Management
```bash
# Access MinIO client
mc alias set local http://localhost:9000 admin password123
mc ls local/clusterfuzz/

# View fuzzing artifacts
mc ls local/clusterfuzz/corpus/
mc ls local/clusterfuzz/crashes/
```

### Database Management
```bash
# Connect to PostgreSQL
PGPASSWORD=generated_password psql \
  -h localhost -p 5432 \
  -U clusterfuzz -d clusterfuzz

# View testcases
SELECT crash_type, count(*) FROM clusterfuzz.testcases 
GROUP BY crash_type;
```

## Configuration Files

The deployment generates configuration in `./clusterfuzz-config/`:

```
clusterfuzz-config/
├── jobs/
│   ├── clusterfuzz-core.nomad    # Core services job
│   └── clusterfuzz-bots.nomad    # Fuzzing bots job
├── env/
│   ├── core.env                  # Core environment vars
│   └── bots.env                  # Bot environment vars
├── init/
│   ├── db-setup.sql             # Database schema
│   └── storage-setup.sh         # Storage initialization
├── docker/
│   ├── web.Dockerfile           # Web interface image
│   ├── bot.Dockerfile           # Bot image
│   └── patches/                 # Non-GCP patches
└── terraform/
    └── main.tf                  # Optional Terraform config
```

## Security Considerations

### Authentication
- **Default**: Authentication disabled for local development
- **Production**: Configure OAuth or LDAP integration

### Network Security
- **Internal**: Services communicate via Consul service discovery
- **External**: Only web interface exposed by default
- **TLS**: Configure TLS termination at load balancer

### Secrets Management
- **Vault Integration**: Store credentials securely
- **Environment Variables**: Passwords generated automatically
- **File Permissions**: Configuration files protected (600)

## Troubleshooting

### Common Issues

#### "Cannot connect to Nomad"
```bash
# Check Nomad connectivity
nomad node status
# Verify address
nomad node status -address=http://your-nomad:4646
```

#### "Database connection failed"
```bash
# Check PostgreSQL is running
nomad alloc status <postgres-alloc>
# Test connection
nc -zv localhost 5432
```

#### "MinIO not accessible"
```bash
# Check MinIO health
curl http://localhost:9000/minio/health/live
# View MinIO logs
nomad alloc logs <minio-alloc>
```

#### "Bots not picking up tasks"
```bash
# Check bot logs
nomad alloc logs <bot-alloc>
# Verify bot registration
curl http://clusterfuzz.local:8080/api/bots
```

### Performance Tuning

#### Bot Scaling
```bash
# Increase regular bots for more task processing
nomad job scale clusterfuzz-bots regular-bots 20

# Increase preemptible bots for more fuzzing
nomad job scale clusterfuzz-bots preemptible-bots 50
```

#### Resource Allocation
Modify job files to increase resources:
```hcl
resources {
  cpu    = 4000    # Increase CPU for faster fuzzing
  memory = 8192    # Increase memory for large targets
}
```

## Advanced Configuration

### Custom Docker Images
Build custom images with additional fuzzing engines:
```bash
# Modify Dockerfiles in clusterfuzz-config/docker/
docker build -t my-clusterfuzz-web:latest \
  -f clusterfuzz-config/docker/web.Dockerfile \
  clusterfuzz-config/docker/

# Update job files to use custom images
```

### External Integrations
- **GitHub Integration**: Webhook for automatic testing
- **JIRA Integration**: Automatic bug filing
- **Slack Notifications**: Crash alerts
- **Prometheus Metrics**: Performance monitoring

## Examples

### Basic Local Development
```bash
eos create clusterfuzz \
  --bot-count 2 \
  --preemptible-bot-count 3 \
  --skip-prereq-check
```

### Production Deployment
```bash
eos create clusterfuzz \
  --domain "clusterfuzz.company.com" \
  --bot-count 10 \
  --preemptible-bot-count 20 \
  --use-vault \
  --vault-path "secret/production/clusterfuzz" \
  --storage-backend s3 \
  --s3-endpoint "https://s3.company.com" \
  --s3-bucket "company-clusterfuzz"
```

### High-Performance Setup
```bash
eos create clusterfuzz \
  --bot-count 50 \
  --preemptible-bot-count 100 \
  --storage-backend s3 \
  --database-backend postgresql \
  --queue-backend redis
```

## Support

For issues and questions:
- **Documentation**: [ClusterFuzz Docs](https://google.github.io/clusterfuzz/)
- **GitHub Issues**: [ClusterFuzz Issues](https://github.com/google/clusterfuzz/issues)
- **Eos Issues**: [Eos GitHub](https://github.com/CodeMonkeyCybersecurity/eos/issues)

The ClusterFuzz deployment provides a powerful, scalable fuzzing infrastructure for discovering security vulnerabilities and improving software quality through continuous automated testing.