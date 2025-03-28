#!/bin/bash

source ./submodules/ubuntu/checkSudo.sh
source ./submodules/ubuntu/yesNo.sh

authorizedKeys="/etc/initramfs-tools/root/.ssh/authorized_keys"
sshDir="/etc/initramfs-tools/root/.ssh"

# Install dropbear-initramfs
if ! sudo apt-get install -y dropbear-initramfs; then
    echo "Failed to install dropbear-initramfs. Please check your internet connection or package sources."
    exit 1
fi

echo "We now need to add your public key to $authorizedKeys"

if ask_yes_no "Do you have your PUBLIC key from your CLIENT computer?"; then
    echo "Remember you can give anyone your PUBLIC key, you must NEVER give someone your PRIVATE key"

    # Ensure the .ssh directory exists
    if ! sudo test -d "$sshDir"; then
        echo "Creating directory $sshDir"
        if ! sudo mkdir -p "$sshDir"; then
            echo "Failed to create directory $sshDir"
            exit 1
        fi
        # Set the correct permissions
        sudo chmod 700 "$sshDir"
        sudo chown root:root "$sshDir"
    fi

    while true; do
        read -p "Paste your CLIENT computer's PUBLIC key here now: " publicKey

        # Trim leading/trailing whitespace
        publicKey=$(echo "$publicKey" | xargs)

        # Validate the key format using regex
        if [[ "$publicKey" =~ ^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521))\ [A-Za-z0-9+/]+={0,3}(\ .*)?$ ]]; then
            # Use ssh-keygen to validate the key
            if echo "$publicKey" | ssh-keygen -l -f /dev/stdin >/dev/null 2>&1; then
                # Append the public key using sudo
                if echo "$publicKey" | sudo tee -a "$authorizedKeys" > /dev/null; then
                    echo "Public key added successfully."
                    # Set the correct permissions
                    sudo chmod 600 "$authorizedKeys"
                    sudo chown root:root "$authorizedKeys"
                    break
                else
                    echo "Failed to write to $authorizedKeys"
                    exit 1
                fi
            else
                echo "Invalid public key. Please ensure the key is correct and try again."
            fi
        else
            echo "The key format is incorrect. Please ensure you're pasting the public key."
        fi
    done
else
    echo "Operation cancelled by the user."
    exit 1
fi

# Update initramfs
if ! sudo update-initramfs -u; then
    echo "Failed to update initramfs. Please check for errors."
    exit 1
fi

echo "Dropbear is now installed and configured."
