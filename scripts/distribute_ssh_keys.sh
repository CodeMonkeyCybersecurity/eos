#!/bin/bash
# distribute_ssh_keys.sh

# Check if Tailscale is running and the machine is part of a Tailscale network
if ! tailscale status > /dev/null 2>&1; then
    echo "This machine is not part of a Tailscale network or Tailscale is not running."
    echo "If you want to install Tailscale, you should run 'install_tailscale.sh'"
    exit 1
else
    echo "Tailscale is up and running and the machine is part of a Tailscale network."
fi

# Get the list of other machines in the Tailscale network
echo "Fetching the list of machines in the Tailscale network..."
TAILSCALE_MACHINES=$(tailscale status --json | jq -r '.Peer[] | "\(.HostName) (\(.TailAddr))"' | grep -v "$(hostname)")

if [ -z "$TAILSCALE_MACHINES" ]; then
    echo "No other machines found in the Tailscale network."
    exit 1
fi

echo "The following machines are in the Tailscale network:"
echo "$TAILSCALE_MACHINES"

# Prompt the user to select the machines
echo "Enter the hostnames or IP addresses of the machines you want to distribute the SSH key to (space-separated):"
read -r -a TAILSCALE_HOSTS

# Confirm the hosts with the user
echo "You entered the following hosts: ${TAILSCALE_HOSTS[@]}"
echo "Is this correct? (y/n)"
read -r CONFIRMATION

if [[ "$CONFIRMATION" != "y" ]]; then
    echo "Exiting script."
    exit 1
fi

# Path to the SSH public key
SSH_KEY=$(cat ~/.ssh/id_rsa.pub)

# Distribute the SSH key to the specified hosts
for HOST in "${TAILSCALE_HOSTS[@]}"; do
    echo "Copying SSH key to $HOST..."
    ssh root@$HOST "mkdir -p ~/.ssh && echo '$SSH_KEY' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && chmod 700 ~/.ssh"
done

echo "SSH key distributed to: ${TAILSCALE_HOSTS[@]}"