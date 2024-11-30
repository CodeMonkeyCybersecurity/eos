#!/bin/bash

# Function for error handling
error_exit() {
    echo "[Error] $1" >&2
    exit 1
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Update and install dependencies
install_dependencies() {
    echo "[Info] Installing required packages..."
    sudo apt update || error_exit "Failed to update package list."
    sudo apt-add-repository -ss
    sudo apt install -y nginx dpkg-dev gcc make build-essential \
        autoconf automake libtool libcurl4-openssl-dev \
        liblua5.3-dev libpcre2-dev libfuzzy-dev ssdeep gettext \
        pkg-config libpcre3 libpcre3-dev libxml2 libxml2-dev \
        libcurl4 libgeoip-dev libyajl-dev doxygen \
        software-properties-common \
        git software-properties-common wget || error_exit "Failed to install dependencies."
}

# Install Nginx
install_nginx() {
    echo "[Info] Installing Nginx..."
    sudo apt install -y nginx || error_exit "Failed to install Nginx."
}

# Check Nginx version
check_nginx_version() {
    echo "[Info] Checking Nginx compatibility..."
    nginx -V 2>&1 | grep -- "--with-compat" || error_exit "Nginx is not compiled with '--with-compat'. Please install a compatible version."
}

# Download and compile ModSecurity
setup_modsecurity() {
    echo "[Info] Setting up ModSecurity..."
    sudo git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity /usr/local/src/ModSecurity/ || error_exit "Failed to clone ModSecurity."
    cd /usr/local/src/ModSecurity/ || error_exit "Failed to navigate to ModSecurity directory."
    sudo git submodule init || error_exit "Failed to initialize submodules."
    sudo git submodule update || error_exit "Failed to update submodules."
    sudo ./build.sh || error_exit "Failed to build ModSecurity."
    sudo ./configure || error_exit "Failed to configure ModSecurity."
    sudo make -j$(nproc) || error_exit "Failed to compile ModSecurity."
    sudo make install || error_exit "Failed to install ModSecurity."
}

# Compile ModSecurity Nginx connector
compile_nginx_connector() {
    mkdir -p /usr/local/src/nginx/
    echo "[Info] Compiling ModSecurity Nginx connector..."
    sudo git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git /usr/local/src/ModSecurity-nginx/ || error_exit "Failed to clone ModSecurity Nginx connector."
    cd /usr/local/src/nginx/ || error_exit "Failed to navigate to Nginx source directory."
    sudo ./configure --with-compat --add-dynamic-module=/usr/local/src/ModSecurity-nginx || error_exit "Failed to configure Nginx for ModSecurity."
    sudo make modules || error_exit "Failed to build ModSecurity Nginx module."
    sudo cp objs/ngx_http_modsecurity_module.so /usr/share/nginx/modules/ || error_exit "Failed to copy ModSecurity module."
}

# Configure Nginx for ModSecurity
configure_nginx() {
    echo "[Info] Configuring Nginx..."
    sudo mkdir -p /etc/nginx/modsec || error_exit "Failed to create ModSecurity configuration directory."
    sudo cp /usr/local/src/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf || error_exit "Failed to copy ModSecurity configuration."
    sudo cp /usr/local/src/ModSecurity/unicode.mapping /etc/nginx/modsec/ || error_exit "Failed to copy unicode mapping file."
    sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf || error_exit "Failed to enable SecRuleEngine."
    echo "Include /etc/nginx/modsec/modsecurity.conf;" | sudo tee -a /etc/nginx/modsec/main.conf >/dev/null
    echo "Include /etc/nginx/modsec/coreruleset-3.3.4/crs-setup.conf;" | sudo tee -a /etc/nginx/modsec/main.conf >/dev/null
    echo "Include /etc/nginx/modsec/coreruleset-3.3.4/rules/*.conf;" | sudo tee -a /etc/nginx/modsec/main.conf >/dev/null
    echo "load_module modules/ngx_http_modsecurity_module.so;" | sudo tee -a /etc/nginx/nginx.conf >/dev/null
    sudo nginx -t || error_exit "Nginx configuration test failed."
    sudo systemctl restart nginx || error_exit "Failed to restart Nginx."
}

# Download and enable OWASP CRS
setup_owasp_crs() {
    echo "[Info] Setting up OWASP Core Rule Set..."
    wget https://github.com/coreruleset/coreruleset/archive/v3.3.4.tar.gz || error_exit "Failed to download OWASP CRS."
    tar xvf v3.3.4.tar.gz || error_exit "Failed to extract OWASP CRS."
    sudo mv coreruleset-3.3.4 /etc/nginx/modsec/ || error_exit "Failed to move OWASP CRS."
    sudo mv /etc/nginx/modsec/coreruleset-3.3.4/crs-setup.conf.example /etc/nginx/modsec/coreruleset-3.3.4/crs-setup.conf || error_exit "Failed to rename CRS configuration."
}

# Main function
main() {
    install_dependencies
    install_nginx
    check_nginx_version
    setup_modsecurity
    compile_nginx_connector
    configure_nginx
    setup_owasp_crs
    echo "[Success] ModSecurity with Nginx has been successfully set up."
}

main

# credit that to https://www.linuxbabe.com/security/modsecurity-nginx-debian-ubuntu for the amazing instructions!
