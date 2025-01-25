#!/bin/bash
# TEST ; IS NOT COMPLETE
# Script to automate 2FA setup in the terminal using oathtool

# Function to check if oathtool and libpam-oath are installed
check_dependencies() {
    if ! command -v oathtool &>/dev/null; then
        echo "Error: oathtool is not installed."
        echo "Please install it using your package manager (e.g., sudo apt install oathtool)."
        exit 1
    fi

    if ! dpkg -l | grep -q "libpam-oath"; then
        echo "Error: libpam-oath is not installed."
        echo "Please install it using your package manager (e.g., sudo apt install libpam-oath)."
        exit 1
    fi
}

# Function to configure 2FA for the user
configure_2fa() {
    echo "Setting up 2FA for user: $USER"
    
    # Generate a new TOTP secret
    SECRET=$(head -c 20 /dev/urandom | base32)
    echo "Your new secret is: $SECRET"
    
    # Save the secret to the user's OATH file
    OATH_FILE="/etc/users.oath"
    echo "HOTP/T30 $USER - $SECRET" | sudo tee -a "$OATH_FILE"
    sudo chmod 600 "$OATH_FILE"
    sudo chown root:root "$OATH_FILE"
    
    echo "2FA has been configured. Use the secret above to set up your authenticator app."
}

# Function to configure PAM for SSH
configure_pam() {
    PAM_FILE="/etc/pam.d/sshd"
    if ! grep -q "pam_oath.so" "$PAM_FILE"; then
        echo "auth required pam_oath.so usersfile=/etc/users.oath window=3" | sudo tee -a "$PAM_FILE"
        echo "Updated $PAM_FILE to enable 2FA."
    else
        echo "PAM is already configured for 2FA."
    fi
}

# Function to configure SSH daemon
configure_sshd() {
    SSHD_CONFIG="/etc/ssh/sshd_config"

    sudo sed -i.bak -e "s/^#*\(ChallengeResponseAuthentication\).*/\1 yes/" \
                    -e "s/^#*\(UsePAM\).*/\1 yes/" \
                    "$SSHD_CONFIG"

    # Ensure AuthenticationMethods is added
    if ! grep -q "AuthenticationMethods" "$SSHD_CONFIG"; then
        echo "AuthenticationMethods publickey,keyboard-interactive" | sudo tee -a "$SSHD_CONFIG"
    fi

    echo "SSH configuration updated. Restarting SSH service..."
    sudo systemctl restart sshd
}

# Main script
main() {
    check_dependencies
    configure_2fa
    configure_pam
    configure_sshd

    echo "2FA setup is complete!"
    echo "Make sure to test your SSH login in a new session before closing the current one."
}

main