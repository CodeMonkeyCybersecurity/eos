#!/bin/bash
set -e

# Variables from Terraform
ENVIRONMENT="${environment}"
COMPONENT="${component}"
CONSUL_ADDR="${consul_addr}"
VAULT_ADDR="${vault_addr}"
SERVICES="${services}"

# Update system
apt-get update
apt-get upgrade -y

# Install required packages
apt-get install -y \
    curl \
    wget \
    unzip \
    jq \
    docker.io \
    docker-compose \
    python3-pip \
    python3-venv \
    git \
    gnupg \
    lsb-release \
    ca-certificates \
    apt-transport-https \
    software-properties-common

# Enable and start Docker
systemctl enable docker
systemctl start docker

# Install Salt Minion
curl -fsSL https://repo.saltproject.io/py3/ubuntu/22.04/amd64/latest/SALTSTACK-GPG-KEY.pub | apt-key add -
echo "deb https://repo.saltproject.io/py3/ubuntu/22.04/amd64/latest jammy main" > /etc/apt/sources.list.d/saltstack.list
apt-get update
apt-get install -y salt-minion

# Configure Salt Minion
cat > /etc/salt/minion <<EOF
master: salt.service.consul
id: hecate-${ENVIRONMENT}-$(hostname -s)
grains:
  roles:
    - hecate
    - reverse-proxy
  environment: ${ENVIRONMENT}
  component: ${COMPONENT}
  services: ${SERVICES}
EOF

# Start Salt Minion
systemctl enable salt-minion
systemctl start salt-minion

# Install Consul agent
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
node_name = "hecate-${ENVIRONMENT}-$(hostname -s)"
server = false

retry_join = ["${CONSUL_ADDR}"]

services {
  name = "hecate"
  port = 80
  tags = ["reverse-proxy", "${ENVIRONMENT}"]
  check {
    http = "http://localhost/health"
    interval = "30s"
  }
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

# Install Nomad client
NOMAD_VERSION="1.7.2"
wget -O nomad.zip "https://releases.hashicorp.com/nomad/${NOMAD_VERSION}/nomad_${NOMAD_VERSION}_linux_amd64.zip"
unzip nomad.zip
mv nomad /usr/local/bin/
rm nomad.zip

# Create Nomad configuration
mkdir -p /etc/nomad.d
cat > /etc/nomad.d/nomad.hcl <<EOF
datacenter = "dc1"
data_dir = "/opt/nomad"
log_level = "INFO"

client {
  enabled = true
  servers = ["nomad.service.consul:4647"]
  
  meta {
    environment = "${ENVIRONMENT}"
    component = "${COMPONENT}"
  }
}

consul {
  address = "127.0.0.1:8500"
}

plugin "docker" {
  config {
    volumes {
      enabled = true
    }
  }
}

telemetry {
  prometheus_metrics = true
}
EOF

# Create Nomad systemd service
cat > /etc/systemd/system/nomad.service <<EOF
[Unit]
Description=Nomad
Documentation=https://nomadproject.io/docs/
Wants=network-online.target
After=network-online.target

[Service]
ExecReload=/bin/kill -HUP \$MAINPID
ExecStart=/usr/local/bin/nomad agent -config /etc/nomad.d
KillMode=process
KillSignal=SIGINT
LimitNOFILE=65536
LimitNPROC=infinity
Restart=on-failure
RestartSec=2
StartLimitBurst=3
TasksMax=infinity
OOMScoreAdjust=-1000

[Install]
WantedBy=multi-user.target
EOF

# Create nomad data directory
mkdir -p /opt/nomad

# Start Nomad
systemctl enable nomad
systemctl start nomad

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

# Install Docker networks for services
docker network create hecate-network || true

# Create necessary directories
mkdir -p /opt/hecate/{config,data,logs}

# Wait for Salt to configure the system
echo "Waiting for Salt configuration..."
sleep 30

# Trigger Salt highstate
salt-call state.highstate || true

# Configure log rotation
cat > /etc/logrotate.d/hecate <<EOF
/opt/hecate/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}
EOF

# Set up health check endpoint
mkdir -p /var/www/html
echo "OK" > /var/www/html/health

# Install and configure Caddy as temporary web server for health checks
apt-get install -y caddy

cat > /etc/caddy/Caddyfile <<EOF
:80 {
    root * /var/www/html
    file_server
    
    handle /health {
        respond "OK" 200
    }
}
EOF

systemctl enable caddy
systemctl restart caddy

echo "Hecate node initialization complete"