#!/bin/bash
# create_ssh_key.sh

# Function to print available key types
function print_key_types {
    echo "1) RSA"
    echo "2) DSA (deprecated)"
    echo "3) ECDSA"
    echo "4) ED25519"
}

# Prompt for the email address
read -p "Enter your email address: " email

# Check if the email is not empty
if [[ -z "$email" ]]; then
    echo "Email address cannot be empty!"
    exit 1
fi

# Prompt for key type
echo "Select the encryption protocol:"
print_key_types
read -p "Enter choice (1-4): " key_choice

# Validate key choice and set key type
case $key_choice in
    1)
        key_type="rsa"
        read -p "Enter key length (2048 or 4096 recommended): " key_length
        ;;
    2)
        key_type="dsa"
        echo "Note: DSA is deprecated and limited to 1024 bits."
        key_length=1024
        ;;
    3)
        key_type="ecdsa"
        echo "Enter key length (256, 384, or 521):"
        read key_length
        ;;
    4)
        key_type="ed25519"
        echo "Note: ED25519 does not require a key length."
        ;;
    *)
        echo "Invalid choice."
        exit 1
        ;;
esac

# Prompt for custom file location (optional)
read -p "Enter file in which to save the key (/home/$USER/.ssh/id_rsa): " file
file="${file:-/home/$USER/.ssh/id_rsa}"  # Default value

# Create the .ssh directory if it doesn't exist
mkdir -p "$(dirname "$file")"

# Prompt for passphrase (optional)
echo "Enter passphrase (empty for no passphrase):"
read -s passphrase

# Generate the SSH key
if [[ $key_type == "ed25519" ]]; then
    ssh-keygen -t $key_type -C "$email" -f "$file" -N "$passphrase"
else
    ssh-keygen -t $key_type -b $key_length -C "$email" -f "$file" -N "$passphrase"
fi

echo "SSH key generated successfully at $file with type $key_type."
