#!/bin/bash

# Function to check for errors
check_error() {
  if [ $? -ne 0 ]; then
    echo "Error encountered: $1. Exiting."
    exit 1
  fi
}

# Update system
echo "Updating the eos_unix..."
sudo apt update && sudo apt upgrade -y
check_error "System update failed"

# Install dependencies
echo "Installing dependencies..."
sudo apt install curl jq -y
check_error "Dependency installation failed"

# Download and install Headscale
echo "Downloading the latest Headscale version..."
HEADSCALE_VERSION=$(curl -s "https://api.github.com/repos/juanfont/headscale/releases/latest" | jq -r .tag_name)
curl -Lo headscale "https://github.com/juanfont/headscale/releases/download/${HEADSCALE_VERSION}/headscale_$(uname -s)_$(uname -m)"
check_error "Failed to download Headscale"

echo "Installing Headscale..."
chmod +x headscale
sudo mv headscale /usr/local/bin/
check_error "Failed to install Headscale"

# Create configuration directory
echo "Creating Headscale configuration directory..."
sudo mkdir -p /etc/headscale

# Generate configuration file
echo "Generating Headscale configuration file..."
headscale generate config > headscale.conf
check_error "Failed to generate configuration file"
sudo mv headscale.conf /etc/headscale/

# Prompt user for configuration setup
echo "Please enter the server URL for Headscale (e.g., http://localhost:8080):"
read -r SERVER_URL

# Replace server_url in the configuration file
sudo sed -i "s|^server_url:.*|server_url: ${SERVER_URL}|" /etc/headscale/headscale.conf

# Set up the database
echo "Setting up the Headscale database..."
headscale migrate
check_error "Database setup failed"

# Create systemd service file
echo "Setting up Headscale as a systemd service..."
cat <<EOF | sudo tee /etc/systemd/system/headscale.service
[Unit]
Description=Headscale
After=network.target

[Service]
Type=notify
User=root
ExecStart=/usr/local/bin/headscale serve
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable headscale --now
check_error "Failed to start Headscale service"

# Check the status of the service
sudo systemctl status headscale

# Prompt user to create a new user for Headscale
echo "Please enter a username for Headscale:"
read -r HEADSCALE_USER

headscale users create "${HEADSCALE_USER}"
check_error "Failed to create Headscale user"

# Generate a pre-authentication key
echo "Generating a reusable pre-authentication key (valid for 24 hours)..."
PREAUTH_KEY=$(headscale preauthkeys create --reusable --expiration 24h --user "${HEADSCALE_USER}" | grep 'key:' | awk '{print $2}')
check_error "Failed to generate pre-authentication key"

echo "Pre-authentication key generated: ${PREAUTH_KEY}"

# Open necessary ports in the firewall
echo "Opening necessary ports in the firewall..."
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 41641/udp
check_error "Failed to open firewall ports"

echo "Headscale setup completed successfully!"
echo "Use the following pre-authentication key on your Tailscale clients to connect:"
echo "${PREAUTH_KEY}"

echo "finis"
