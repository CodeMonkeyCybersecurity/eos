# Eos Assets Directory

This directory contains all deployment assets for the Eos security monitoring platform, including the Wazuh data pipeline, service configurations, and supporting resources.

## Directory Structure

```
assets/
├── README.md                    # This file
├── email.html                   # HTML email template for alerts
├── python_workers/              # Core Wazuh pipeline services
│   ├── alert-to-db.py           # Ingests alerts into PostgreSQL
│   ├── custom-wazuh-webhook.py # Wazuh webhook integration
│   ├── wazuh-agent-enricher.py # Agent enrichment service
│   ├── wazuh-emailer.py        # Email notification service
│   ├── wazuh-listener.py       # HTTP webhook listener
│   └── llm-worker.py            # LLM processing service
├── services/                    # Systemd service files
│   ├── wazuh-agent-enricher.service
│   ├── wazuh-emailer.service
│   ├── wazuh-listener.service
│   └── llm-worker.service
└── stackstorm_rules/            # StackStorm integration
    ├── pack.yaml                # StackStorm pack definition
    └── stackstorm-webhook.yml    # Webhook rule configuration
```

## Core Components

### 🐍 Python Workers (`python_workers/`)

The Wazuh security monitoring pipeline consists of six interconnected Python services that process security alerts from Wazuh through to email notifications.

#### **Data Flow Pipeline**
```
Wazuh → custom-wazuh-webhook.py → wazuh-listener.py → alert-to-db.py → wazuh-agent-enricher.py → llm-worker.py → wazuh-emailer.py
```

#### **Service Descriptions**

##### 1. **custom-wazuh-webhook.py**
- **Purpose**: Wazuh integration script that sends alerts to the Wazuh listener
- **Location**: `/var/ossec/integrations/custom-wazuh-webhook.py`
- **Permissions**: `root:wazuh 0750`
- **Dependencies**: `requests`
- **Features**:
  - Receives alerts from Wazuh manager
  - Forwards to wazuh-listener via HTTP POST
  - Uses X-Auth-Token for authentication
  - Includes test mode with `--test` flag
  - Logs payloads for debugging

##### 2. **wazuh-listener.py**
- **Purpose**: HTTP webhook listener that receives alerts from Wazuh
- **Port**: 9000 (configurable)
- **Dependencies**: `python-dotenv` (optional)
- **Features**:
  - Threaded HTTP server for concurrent requests
  - Token-based authentication
  - Calls alert-to-db.py to process alerts
  - Comprehensive logging and error handling
  - Graceful shutdown handling

##### 3. **alert-to-db.py**
- **Purpose**: Ingests raw alerts into PostgreSQL database
- **Dependencies**: `psycopg2-binary`, `python-dotenv`
- **Features**:
  - Deduplication using hash-based detection
  - ON CONFLICT handling for concurrent inserts
  - PostgreSQL NOTIFY for real-time updates
  - Comprehensive error handling and logging
  - Configurable via environment variables

##### 4. **wazuh-agent-enricher.py**
- **Purpose**: Enriches alerts with agent information from Wazuh API
- **Dependencies**: `requests`, `psycopg2-binary`, `python-dotenv`
- **Features**:
  - Listens for PostgreSQL notifications
  - Fetches agent details via Wazuh API
  - Updates agent information in database
  - JWT token management with auto-refresh
  - Comprehensive database transaction handling

##### 5. **llm-worker.py**
- **Purpose**: Processes alerts using Azure OpenAI for intelligent analysis
- **Dependencies**: `requests`, `psycopg2-binary`, `python-dotenv`
- **Features**:
  - Azure OpenAI integration
  - Configurable LLM prompts
  - Alert analysis and recommendation generation
  - Database state management
  - Error handling and retry logic

##### 6. **wazuh-emailer.py**
- **Purpose**: Sends email notifications for processed alerts
- **Dependencies**: `psycopg2-binary`, `python-dotenv`, `pytz`
- **Features**:
  - HTML email templates
  - SMTP configuration
  - Timezone-aware timestamps
  - Batch processing capabilities
  - Email delivery tracking

#### **Environment Configuration**

All services read configuration from `/opt/stackstorm/packs/wazuh/.env`:

```bash
# Database Configuration
PG_DSN="postgresql://user:password@localhost:5432/wazuh"
AGENTS_PG_DSN="postgresql://user:password@localhost:5432/wazuh"

# Wazuh API Configuration
WAZUH_API_URL="https://wazuh-manager:55000"
WAZUH_API_USER="wazuh-api-user"
WAZUH_API_PASSWD="wazuh-api-password"

# Azure OpenAI Configuration
AZURE_OPENAI_ENDPOINT="https://your-endpoint.openai.azure.com/"
AZURE_OPENAI_API_KEY="your-api-key"
AZURE_OPENAI_DEPLOYMENT_NAME="your-deployment"

# Email Configuration
SMTP_SERVER="smtp.example.com"
SMTP_PORT="587"
SMTP_USERNAME="alerts@example.com"
SMTP_PASSWORD="smtp-password"
EMAIL_FROM="alerts@example.com"
EMAIL_TO="admin@example.com"

# Authentication
WEBHOOK_AUTH_TOKEN="your-secure-token"
```

###  Service Files (`services/`)

Systemd service files for managing the Wazuh pipeline services.

#### **Service Features**
- **Security Hardening**: `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=strict`
- **Resource Limits**: Memory (1G) and CPU (80%) quotas
- **Restart Policies**: Automatic restart with exponential backoff
- **Dependency Management**: Proper service ordering and dependencies

#### **Service Management**
```bash
# Install dependencies
sudo eos wazuh services preflight-install

# Start all services
sudo eos wazuh services start --all

# Check status
sudo eos wazuh services status --all

# View logs
sudo eos wazuh services logs wazuh-listener
```

###  Email Template (`email.html`)

Professional HTML email template for security alert notifications.

#### **Features**
- Responsive design with modern styling
- Template variables for dynamic content
- Clean, professional appearance
- Cross-client compatibility
- Security-focused color scheme

#### **Template Variables**
- `$subject` - Email subject line
- `$timestamp` - Alert timestamp
- `$content` - Alert details and analysis
- Additional variables populated by wazuh-emailer.py

###  StackStorm Integration (`stackstorm_rules/`)

StackStorm pack configuration for workflow automation.

#### **Components**
- **pack.yaml**: Pack metadata and configuration
- **stackstorm-webhook.yml**: Webhook rule definitions

#### **Features**
- Automated alert processing workflows
- Integration with StackStorm automation platform
- Configurable rule triggers and actions

## Installation and Deployment

### **Prerequisites**
```bash
# Install Python dependencies
sudo eos wazuh services preflight-install

# Install PostgreSQL
sudo apt install postgresql postgresql-contrib

# Install Wazuh (refer to Wazuh documentation)
```

### **Database Setup**
```sql
-- Create database and user
CREATE DATABASE wazuh;
CREATE USER wazuh_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE wazuh TO wazuh_user;

-- Apply schema (see sql/schema.sql)
```

### **Service Deployment**
```bash
# Deploy Wazuh services
sudo eos create wazuh

# Deploy webhook integration
sudo eos create wazuh-webhook

# Start services
sudo eos wazuh services start --all
```

### **Configuration**
1. Create `/opt/stackstorm/packs/wazuh/.env` with required variables
2. Configure Wazuh integration in `/var/ossec/etc/ossec.conf`
3. Set up email SMTP configuration
4. Configure Azure OpenAI credentials

## Monitoring and Troubleshooting

### **Log Locations**
- **Service Logs**: `journalctl -u <service-name> -f`
- **Application Logs**: `/var/log/stackstorm/`
- **Eos Logs**: `/var/log/eos/eos.log`

### **Health Checks**
```bash
# Check service status
sudo eos wazuh services status --all

# Check Python dependencies
sudo eos wazuh services check

# View real-time alerts
sudo eos wazuh watch alerts

# View agent status
sudo eos wazuh watch agents
```

### **Common Issues**
1. **Missing Dependencies**: Run `sudo eos wazuh services preflight-install`
2. **Database Connection**: Verify PostgreSQL is running and DSN is correct
3. **Wazuh API**: Check API credentials and network connectivity
4. **Email Delivery**: Verify SMTP configuration and credentials

## Security Considerations

### **File Permissions**
- Python workers: `stanley:stanley 0750`
- Service files: `root:root 0644`
- Configuration files: `root:root 0600`

### **Network Security**
- webhook-listener: Bound to localhost by default
- Authentication tokens for all API communications
- TLS encryption for external connections

### **Data Protection**
- Sensitive data encrypted at rest in PostgreSQL
- Environment variables for credential management
- Proper logging without credential exposure

## Integration Points

### **Wazuh Integration**
- Custom webhook script in `/var/ossec/integrations/`
- Configured via Wazuh manager `ossec.conf`
- Real-time alert forwarding

### **Database Integration**
- PostgreSQL with JSONB for flexible alert storage
- LISTEN/NOTIFY for real-time event processing
- Proper indexing for performance

### **Email Integration**
- SMTP support for email notifications
- HTML templates for professional appearance
- Timezone-aware timestamp handling

### **LLM Integration**
- Azure OpenAI for intelligent alert analysis
- Configurable prompts and models
- Response caching and error handling

## Development and Customization

### **Adding New Workers**
1. Create new Python file in `python_workers/`
2. Add corresponding systemd service file
3. Update environment configuration
4. Register with Eos command system

### **Modifying Templates**
- Email templates: Edit `email.html`
- Service templates: Modify service files in `services/`
- Configuration templates: Update environment examples

### **Database Schema Changes**
- Modify schema in `sql/schema.sql`
- Update Python workers to handle new fields
- Test migration procedures

## Support and Maintenance

### **Backup Procedures**
- Database: Regular PostgreSQL dumps
- Configuration: Backup `/opt/stackstorm/packs/wazuh/`
- Logs: Archive important log files

### **Update Procedures**
1. Stop services: `sudo eos wazuh services stop --all`
2. Update code and configurations
3. Restart services: `sudo eos wazuh services start --all`
4. Verify functionality

### **Scaling Considerations**
- Multiple worker instances for high throughput
- Database connection pooling
- Load balancing for webhook listeners
- Asynchronous processing queues

---

**Contact**: Code Monkey Cybersecurity  
**Email**: main@cybermonkey.net.au  
**Documentation**: [Athena Knowledge Base](https://wiki.cybermonkey.net.au)