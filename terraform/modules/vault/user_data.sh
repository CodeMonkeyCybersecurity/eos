#!/bin/bash
set -e

# Variables from Terraform
ENVIRONMENT="${environment}"
COMPONENT="${component}"
CLUSTER_SIZE="${cluster_size}"
CONSUL_CLUSTER_TAG="${consul_cluster_tag}"
KMS_KEY_ID="${kms_key_id}"
AWS_REGION="${aws_region}"

# Update system
apt-get update
apt-get upgrade -y

# Install required packages
apt-get install -y \
    curl \
    wget \
    unzip \
    jq \
    awscli \
    python3-pip

# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install
rm -rf awscliv2.zip aws/

# Get instance metadata
INSTANCE_ID=$(ec2-metadata --instance-id | cut -d " " -f 2)
PRIVATE_IP=$(ec2-metadata --local-ipv4 | cut -d " " -f 2)
PUBLIC_IP=$(ec2-metadata --public-ipv4 | cut -d " " -f 2 || echo "")

# Install Consul
CONSUL_VERSION="1.17.0"
wget -O consul.zip "https://releases.hashicorp.com/consul/${CONSUL_VERSION}/consul_${CONSUL_VERSION}_linux_amd64.zip"
unzip consul.zip
mv consul /usr/local/bin/
rm consul.zip

# Create Consul configuration
mkdir -p /etc/consul.d
cat > /etc/consul.d/consul.hcl <<EOF
datacenter = "dc1"
data_dir = "/opt/consul"
log_level = "INFO"
node_name = "vault-${ENVIRONMENT}-${INSTANCE_ID}"
server = true
bootstrap_expect = ${CLUSTER_SIZE}

# Cloud auto-join
retry_join = ["provider=aws tag_key=${CONSUL_CLUSTER_TAG} tag_value=true"]

ui_config {
  enabled = true
}

connect {
  enabled = true
}

ports {
  grpc = 8502
}

telemetry {
  prometheus_retention_time = "30s"
}

encrypt = "$(consul keygen)"
EOF

# Create Consul systemd service
cat > /etc/systemd/system/consul.service <<EOF
[Unit]
Description=Consul
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/consul.d/consul.hcl

[Service]
Type=notify
User=consul
Group=consul
ExecStart=/usr/local/bin/consul agent -config-dir=/etc/consul.d/
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Create consul user
useradd --system --home /etc/consul.d --shell /bin/false consul
mkdir -p /opt/consul
chown -R consul:consul /opt/consul /etc/consul.d

# Start Consul
systemctl enable consul
systemctl start consul

# Wait for Consul to be ready
sleep 30

# Install Vault
VAULT_VERSION="1.15.4"
wget -O vault.zip "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip"
unzip vault.zip
mv vault /usr/local/bin/
rm vault.zip

# Create Vault configuration
mkdir -p /etc/vault.d
cat > /etc/vault.d/vault.hcl <<EOF
ui = true
disable_mlock = true

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = 1
}

storage "consul" {
  address = "127.0.0.1:8500"
  path    = "vault/"
}

service_registration "consul" {
  address = "127.0.0.1:8500"
}

api_addr = "http://${PRIVATE_IP}:8200"
cluster_addr = "http://${PRIVATE_IP}:8201"

cluster_name = "vault-${ENVIRONMENT}"

telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
}
EOF

# Add KMS auto-unseal if enabled
if [ -n "${KMS_KEY_ID}" ]; then
  cat >> /etc/vault.d/vault.hcl <<EOF

seal "awskms" {
  region     = "${AWS_REGION}"
  kms_key_id = "${KMS_KEY_ID}"
}
EOF
fi

# Create Vault systemd service
cat > /etc/systemd/system/vault.service <<EOF
[Unit]
Description=Vault
Documentation=https://www.vaultproject.io/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/vault.d/vault.hcl
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=notify
EnvironmentFile=-/etc/vault.d/vault.env
User=vault
Group=vault
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
SecureBits=keep-caps
AmbientCapabilities=CAP_IPC_LOCK
CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
NoNewPrivileges=yes
ExecStart=/usr/local/bin/vault server -config=/etc/vault.d/vault.hcl
ExecReload=/bin/kill --signal HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

# Create vault user
useradd --system --home /etc/vault.d --shell /bin/false vault

# Set up Vault data directory
mkdir -p /opt/vault/data
chown -R vault:vault /opt/vault /etc/vault.d

# Start Vault
systemctl enable vault
systemctl start vault

# Set VAULT_ADDR for commands
export VAULT_ADDR="http://127.0.0.1:8200"

# Install Salt Minion
curl -fsSL https://repo.saltproject.io/py3/ubuntu/22.04/amd64/latest/SALTSTACK-GPG-KEY.pub | apt-key add -
echo "deb https://repo.saltproject.io/py3/ubuntu/22.04/amd64/latest jammy main" > /etc/apt/sources.list.d/saltstack.list
apt-get update
apt-get install -y salt-minion

# Configure Salt Minion
cat > /etc/salt/minion <<EOF
master: salt.service.consul
id: vault-${ENVIRONMENT}-${INSTANCE_ID}
grains:
  roles:
    - vault
  environment: ${ENVIRONMENT}
  component: ${COMPONENT}
  vault_addr: http://${PRIVATE_IP}:8200
EOF

# Start Salt Minion
systemctl enable salt-minion
systemctl start salt-minion

# Create backup script
cat > /usr/local/bin/vault-backup.sh <<'EOF'
#!/bin/bash
set -e

BACKUP_BUCKET="s3://vault-${ENVIRONMENT}-backups-$(aws sts get-caller-identity --query Account --output text)"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="vault-backup-${TIMESTAMP}.snap"

# Create backup
vault operator raft snapshot save /tmp/${BACKUP_FILE}

# Upload to S3
aws s3 cp /tmp/${BACKUP_FILE} ${BACKUP_BUCKET}/${BACKUP_FILE}

# Clean up local file
rm /tmp/${BACKUP_FILE}

echo "Backup completed: ${BACKUP_FILE}"
EOF

chmod +x /usr/local/bin/vault-backup.sh

# Create backup cron job
echo "0 2 * * * vault /usr/local/bin/vault-backup.sh >> /var/log/vault-backup.log 2>&1" | crontab -u vault -

# Install Node Exporter for monitoring
NODE_EXPORTER_VERSION="1.7.0"
wget -O node_exporter.tar.gz "https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz"
tar xvf node_exporter.tar.gz
mv node_exporter-*/node_exporter /usr/local/bin/
rm -rf node_exporter-* node_exporter.tar.gz

# Create Node Exporter systemd service
cat > /etc/systemd/system/node_exporter.service <<EOF
[Unit]
Description=Node Exporter
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
EOF

# Start Node Exporter
systemctl enable node_exporter
systemctl start node_exporter

# Register Node Exporter with Consul
cat > /etc/consul.d/node_exporter.json <<EOF
{
  "service": {
    "name": "node-exporter",
    "tags": ["monitoring"],
    "port": 9100,
    "check": {
      "http": "http://localhost:9100/metrics",
      "interval": "30s"
    }
  }
}
EOF

# Reload Consul to pick up new service
consul reload

echo "Vault node initialization complete"