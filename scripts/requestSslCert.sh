#!/bin/bash

# Function to check if Certbot is installed
check_certbot_installed() {
    if ! command -v certbot &> /dev/null; then
        echo "Certbot is not installed. Please install Certbot first."
        exit 1
    fi
}

# Function to request an SSL certificate using Certbot
request_certificate() {
    local domain_name="$1"
    local email="$2"
    local agree_tos="$3"
    local webroot_path="$4"

    if [ -z "$domain_name" ] || [ -z "$email" ]; then
        echo "Usage: $0 <domain_name> <email> [webroot_path] [--agree-tos]"
        exit 1
    fi

    # Request SSL certificate using webroot authentication
    if [ -n "$webroot_path" ]; then
        certbot certonly --webroot -w "$webroot_path" -d "$domain_name" --email "$email" --agree-tos --no-eff-email
    else
        # Request SSL certificate using standalone mode
        certbot certonly --standalone -d "$domain_name" --email "$email" --agree-tos --no-eff-email
    fi

    if [ $? -ne 0 ]; then
        echo "Failed to obtain SSL certificate for $domain_name"
        exit 1
    else
        echo "SSL certificate for $domain_name has been successfully obtained."
    fi
}

# Main script execution
main() {
    check_certbot_installed

    read -p "Enter the domain name (e.g., example.com): " domain_name
    read -p "Enter your email address: " email
    read -p "Do you agree to the Let's Encrypt Terms of Service? (yes/no): " agree_tos
    read -p "Enter the webroot path if you want to use webroot authentication (leave blank for standalone mode): " webroot_path

    if [ "$agree_tos" != "yes" ]; then
        echo "You must agree to the Let's Encrypt Terms of Service to obtain a certificate."
        exit 1
    fi

    request_certificate "$domain_name" "$email" "$agree_tos" "$webroot_path"
}

# Run the main function
main
