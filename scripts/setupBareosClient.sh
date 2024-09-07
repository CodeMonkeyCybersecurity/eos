#!/bin/bash

# Function to prompt user for input with a default value
prompt_user() {
    local prompt_text="$1"
    local default_value="$2"
    local input

    read -p "$prompt_text [$default_value]: " input
    echo "${input:-$default_value}"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Determine the operating system and install Bareos FileDaemon
if [ -f /etc/debian_version ]; then
    echo "Detected Debian/Ubuntu. Installing Bareos FileDaemon..."
    apt-get update
    apt-get install -y bareos-filedaemon
elif [ -f /etc/redhat-release ]; then
    echo "Detected CentOS/RedHat. Installing Bareos FileDaemon..."
    yum install -y epel-release
    yum install -y bareos-filedaemon
else
    echo "Unsupported operating system. Exiting..."
    exit 1
fi

# Prompt for necessary details
fd_name=$(prompt_user "Enter the name for this Bareos FileDaemon" "client-fd")
director_name=$(prompt_user "Enter the Bareos Director name" "bareos-dir")
director_password=$(prompt_user "Enter the Bareos Director password" "[md5]9b24f4caf0d40e446e023f94b9d22d0b")
director_address=$(prompt_user "Enter the Director's IP or hostname" "localhost")

# Configure the Bareos FileDaemon
echo "Configuring Bareos FileDaemon..."
cat <<EOF > /etc/bareos/bareos-fd.conf
FileDaemon {                            # this is me
  Name = $fd_name
  FDPort = 9102                 # where we listen for the director
  WorkingDirectory = /var/lib/bareos
  Pid Directory = /var/run/bareos
  Maximum Concurrent Jobs = 10
  Plugin Directory = /usr/lib/bareos/plugins
  PKI Signatures = Yes           # If you want to use TLS/SSL
  PKI Encryption = Yes           # If you want to use TLS/SSL
  TLS Require = Yes              # Require TLS for connections
}

Director {
  Name = $director_name
  Password = "$director_password"  # Use the password set in your Director configuration
}

Messages {
  Name = Standard
  director = $director_name = all, !skipped, !restored
}
EOF

# Restart the Bareos FileDaemon to apply the new configuration
echo "Restarting Bareos FileDaemon..."
systemctl restart bareos-fd

# Output the status of the FileDaemon
echo "Bareos FileDaemon setup is complete. Status:"
systemctl status bareos-fd --no-pager

echo "Remember to add this client configuration to the Bareos Director!"
echo "Client Name: $fd_name"
echo "Client Address: $director_address"
echo "Client Password: $director_password"
