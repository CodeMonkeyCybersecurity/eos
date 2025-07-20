# Automatic Secret and Environment Management

*Last Updated: 2025-01-20*

## Overview

Eos provides automatic secret generation and environment discovery to enable ultra-simple service deployments. Instead of requiring manual configuration, the system intelligently detects the environment and generates secure secrets automatically.

## User Experience Transformation

### **Before (Manual Configuration Required)**
```bash
# User had to specify everything manually
eos create jenkins --admin-password secret123 --datacenter production --environment production
eos create grafana --admin-password mypassword --port 3000 --datacenter dc1

# Problems:
# - Users had to remember/manage passwords
# - Weak passwords often used for convenience  
# - Environment configuration inconsistent
# - Manual coordination of datacenters/regions
```

### **After (Automatic Management)**
```bash
# Simple, automatic deployment
eos create jenkins    # Everything discovered and generated automatically
eos create grafana    # Secure secrets, correct environment

# System automatically:
# - Discovers environment (production/staging/development)
# - Detects datacenter from cloud metadata or bootstrap
# - Generates cryptographically secure secrets
# - Stores secrets in Vault (or SaltStack/file fallback)
# - Uses appropriate resource allocation for environment
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                   User Command                              │
│                eos create grafana                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│              Environment Discovery                          │
│  • Bootstrap state analysis                                │
│  • Salt grains inspection                                  │
│  • Cloud metadata detection                                │
│  • Intelligent defaults                                    │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│              Secret Management                              │
│  • Vault (preferred)                                      │
│  • SaltStack pillar (fallback)                            │
│  • Encrypted file storage (last resort)                   │
│  • Cryptographically secure generation                    │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│           Service Deployment                               │
│  • SaltStack → Terraform → Nomad                          │
│  • Automatic configuration injection                       │
│  • Environment-appropriate resource allocation             │
└─────────────────────────────────────────────────────────────┘
```

## Environment Discovery Process

### **1. Bootstrap State Detection**
The system first checks for existing bootstrap configuration:

```json
// /opt/eos/bootstrap/environment.json (created by eos bootstrap)
{
  "environment": "production",
  "datacenter": "us-east-1", 
  "region": "us-east-1",
  "node_role": "server",
  "cluster_nodes": ["node1", "node2", "node3"]
}
```

### **2. Salt Grains Analysis**
If bootstrap state isn't available, checks Salt grains:

```yaml
# Salt grains contain environment information
environment: production
datacenter: dc1
node_role: server
cloud_provider: hetzner
region: nbg1
```

### **3. Cloud Metadata Detection**
For cloud deployments, queries metadata services:

```bash
# Hetzner Cloud
curl -s http://169.254.169.254/hetzner/v1/metadata

# AWS
curl -s http://169.254.169.254/latest/meta-data/placement/region

# Azure
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance/compute/location"
```

### **4. Intelligent Defaults**
Applies smart defaults based on context:

```go
// Environment determination logic
func determineEnvironmentFromContext(config *EnvironmentConfig) string {
    hostname := strings.ToLower(os.Hostname())
    
    // Hostname pattern detection
    if strings.Contains(hostname, "prod") { return "production" }
    if strings.Contains(hostname, "stag") { return "staging" }
    if strings.Contains(hostname, "dev")  { return "development" }
    
    // Cloud instances default to production
    if config.Region != "" { return "production" }
    
    // Local/unknown defaults to development
    return "development"
}
```

## Secret Management Hierarchy

### **1. Vault Backend (Preferred)**
When Vault is available:
```bash
# Secrets stored in Vault with proper paths
vault kv put secret/services/production/jenkins \
    admin_password="crypto-secure-password" \
    api_token="secure-api-key"

# Automatic secret rotation supported
vault kv put secret/services/production/jenkins \
    admin_password="new-rotated-password"
```

### **2. SaltStack Backend (Fallback)**
When Vault unavailable but Salt is present:
```yaml
# /srv/pillar/secrets/services_production_jenkins.sls
secrets:
  admin_password: crypto-secure-password  
  api_token: secure-api-key
```

### **3. File Backend (Last Resort)**
When neither Vault nor Salt available:
```json
// /opt/eos/secrets/services/production/jenkins.json
{
  "admin_password": "crypto-secure-password",
  "api_token": "secure-api-key",
  "created_at": "2025-01-20T10:30:00Z",
  "backend": "file"
}
```

## Secret Generation Standards

### **Password Generation**
- **Length**: 16 characters minimum
- **Character Set**: Uppercase, lowercase, digits, special characters
- **Entropy**: Cryptographically secure random generation
- **No Ambiguous Characters**: Excludes 0/O, 1/l/I, etc.

### **API Key Generation** 
- **Length**: 32 characters
- **Format**: Base64 URL-safe encoding
- **Entropy**: 256 bits minimum

### **Token Generation**
- **Length**: 24 characters  
- **Format**: Base64 standard encoding
- **Use Case**: Session tokens, temporary access

### **JWT Secrets**
- **Length**: 32 bytes (256 bits)
- **Format**: Base64 encoded
- **Use Case**: JWT signing keys

## Environment-Specific Resource Allocation

### **Development Environment**
```json
{
  "cpu": 100,
  "memory": 256,
  "replicas": 1,
  "max_replicas": 1,
  "storage": "ephemeral"
}
```

### **Staging Environment**  
```json
{
  "cpu": 200,
  "memory": 512,
  "replicas": 1,
  "max_replicas": 2,
  "storage": "persistent"
}
```

### **Production Environment**
```json
{
  "cpu": 500,
  "memory": 1024,
  "replicas": 2,
  "max_replicas": 5,
  "storage": "redundant"
}
```

## Service-Specific Secret Requirements

### **Jenkins**
```go
requiredSecrets := map[string]SecretType{
    "admin_password": SecretTypePassword,
    "api_token":      SecretTypeAPIKey,
    "jwt_secret":     SecretTypeJWT,
}
```

### **Grafana**
```go
requiredSecrets := map[string]SecretType{
    "admin_password":   SecretTypePassword,
    "secret_key":       SecretTypeToken,
    "database_password": SecretTypePassword,
}
```

### **Mattermost**
```go
requiredSecrets := map[string]SecretType{
    "database_password": SecretTypePassword,
    "file_public_key":   SecretTypeAPIKey,
    "file_private_key":  SecretTypeAPIKey,
    "invite_salt":       SecretTypeToken,
}
```

## Implementation in Service Commands

### **Updated Service Command Pattern**
```go
func runCreateGrafana(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // 1. Discover environment automatically
    envConfig, err := environment.DiscoverEnvironment(rc)
    if err != nil {
        return fmt.Errorf("environment discovery failed: %w", err)
    }
    
    // 2. Get or generate secrets automatically
    secretManager, err := secrets.NewSecretManager(rc, envConfig)
    if err != nil {
        return fmt.Errorf("secret manager init failed: %w", err)
    }
    
    requiredSecrets := map[string]secrets.SecretType{
        "admin_password": secrets.SecretTypePassword,
        "secret_key":     secrets.SecretTypeToken,
    }
    
    serviceSecrets, err := secretManager.GetOrGenerateServiceSecrets("grafana", requiredSecrets)
    if err != nil {
        return fmt.Errorf("secret generation failed: %w", err)
    }
    
    // 3. Build configuration with discovered values
    pillarConfig := map[string]interface{}{
        "nomad_service": map[string]interface{}{
            "name":        "grafana",
            "environment": envConfig.Environment,
            "config": map[string]interface{}{
                "admin_password": serviceSecrets.Secrets["admin_password"],
                "secret_key":     serviceSecrets.Secrets["secret_key"],
                "port":          envConfig.Services.DefaultPorts["grafana"],
                "datacenter":    envConfig.Datacenter,
                "cpu":           envConfig.Services.Resources[envConfig.Environment].CPU,
                "memory":        envConfig.Services.Resources[envConfig.Environment].Memory,
                "replicas":      envConfig.Services.Resources[envConfig.Environment].Replicas,
            },
        },
    }
    
    // 4. Deploy with automatically configured values
    logger.Info("Deploying Grafana with automatic configuration",
        zap.String("environment", envConfig.Environment),
        zap.String("datacenter", envConfig.Datacenter),
        zap.String("secret_backend", envConfig.SecretBackend))
    
    if err := applySaltStateWithPillar(rc, "nomad.services", pillarConfig); err != nil {
        return fmt.Errorf("deployment failed: %w", err)
    }
    
    // 5. Display access information
    logger.Info("Grafana deployed successfully",
        zap.String("url", fmt.Sprintf("http://localhost:%d", envConfig.Services.DefaultPorts["grafana"])),
        zap.String("username", "admin"),
        zap.String("password", serviceSecrets.Secrets["admin_password"].(string)),
        zap.String("environment", envConfig.Environment))
    
    return nil
}
```

## Bootstrap Integration

### **Enhanced Bootstrap Command**
The `eos bootstrap` command should be enhanced to set up the environment configuration:

```bash
# eos bootstrap automatically detects and configures environment
eos bootstrap --environment production --datacenter us-east-1 --cluster-size 3

# Creates /opt/eos/bootstrap/environment.json with discovered configuration
# Sets up Salt grains for environment identification
# Configures Vault/Consul for secret management
```

### **Bootstrap Environment Detection**
```go
func runBootstrap(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    // Detect cloud environment
    cloudProvider := detectCloudProvider()
    region := detectRegion(cloudProvider)
    
    // Determine environment from flags or context
    environment := determineEnvironment(cmd, cloudProvider)
    
    // Create environment configuration
    envConfig := &environment.EnvironmentConfig{
        Environment: environment,
        Datacenter:  region,
        Region:      region,
        NodeRole:    "server", // or detect based on cluster
    }
    
    // Save configuration for future service deployments
    if err := saveEnvironmentConfig(envConfig); err != nil {
        return fmt.Errorf("failed to save environment config: %w", err)
    }
    
    // Set up Salt grains
    if err := configureSaltGrains(envConfig); err != nil {
        return fmt.Errorf("failed to configure Salt grains: %w", err)
    }
    
    // Continue with bootstrap process...
}
```

## Security Considerations

### **Secret Storage Security**
- **File Permissions**: 0600 for secret files
- **Directory Permissions**: 0700 for secret directories
- **Encryption at Rest**: Planned future enhancement
- **Access Logging**: All secret access logged

### **Secret Transmission**
- **In-Memory Only**: Secrets never written to logs
- **Encrypted Channels**: Vault communication over TLS
- **Limited Scope**: Secrets only accessible to service processes

### **Secret Rotation**
- **Automatic Detection**: System detects when secrets should be rotated
- **Graceful Updates**: Services updated with new secrets without downtime
- **Backup Retention**: Old secrets retained for rollback scenarios

## Benefits

### **For Users**
- **Ultra-Simple Commands**: `eos create grafana` just works
- **Secure by Default**: Cryptographically strong secrets automatically
- **Consistent Environments**: Same commands work across dev/staging/prod
- **No Password Management**: System handles all secret generation

### **For Operations**
- **Environment Consistency**: Automatic environment detection prevents misconfigurations
- **Secret Management**: Centralized secret storage and rotation
- **Audit Trail**: All secret operations logged and tracked
- **Disaster Recovery**: Secrets backed up and recoverable

### **For Security**
- **Strong Entropy**: All secrets cryptographically generated
- **Proper Storage**: Secrets stored in appropriate backends (Vault preferred)
- **Access Control**: Only authorized services can access secrets
- **Rotation Ready**: Framework supports automatic secret rotation

This system transforms Eos from requiring detailed manual configuration to providing intelligent, automatic deployment with enterprise-grade security.