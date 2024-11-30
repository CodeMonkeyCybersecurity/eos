#!/bin/bash

# Function for error handling
error_exit() {
    echo "[Error] $1" >&2
    exit 1
}

../checkSudo.sh || error_exit "Failed to verify sudo privileges."

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

install_nginx() {
    apt install nginx || error_exit "Failed to install nginx."
    nginx -V || error_exit "Failed to verify nginx version."
    apt install software-properties-common || error_exit "sudo apt install software-properties-common  failed"
    apt-add-repository -ss || error_exit "sudo apt-add-repository -ss failed"
    apt update || error_exit "sudo apt update failed"

download_source() {
    echo "get username..." 
    read -p "Which user would you like to administer nginx?: " INPUT_USER || error_exit "read -p "Which user would you like to administer nginx?: " INPUT_USER failed"
    chown "$INPUT_USER:$INPUT_USER" /usr/local/src/ -R || error_exit "chown "$INPUT_USER:$INPUT_USER" /usr/local/src/ -R failed"
    mkdir -p /usr/local/src/nginx || exit_error "failed to mkdir: /usr/local/src/nginx"
    cd /usr/local/src/nginx/ || exit_error "failed to cd into the Nginx source directory."
    echo "Download Nginx source package: "
    apt install dpkg-dev 
    apt source nginx 
    echo "list the downloaded source files..."
    echo "note the version of nginx which has been installed. You will need to input it in the next step..."
    ls -lah /usr/local/src/nginx/
    read -p "Enter nginx version number (eg. 1.24.0): " VERSION_NUMBER
}

install_libmodsecurity() {
    echo "To compile libmodsecurity, first clone the source code from Github..."
    apt install git || error_exit "Failed to install git"
    git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity /usr/local/src/ModSecurity/ || error_exit "Failed to clone ModSecurity."
    cd /usr/local/src/ModSecurity/ || error_exit "Failed to navigate to ModSecurity directory."
    echo "Install build dependencies..."
    apt install gcc make build-essential autoconf \
    automake libtool libcurl4-openssl-dev liblua5.3-dev libpcre2-dev \
    libfuzzy-dev ssdeep gettext pkg-config libpcre3 libpcre3-dev \
    libxml2 libxml2-dev libcurl4 libgeoip-dev libyajl-dev doxygen \
    uuid-dev || error_exit "Failed to install all dependencies."
    echo "Install required submodules..."
    git submodule init || error_exit "Failed to initialize submodules."
    git submodule update || error_exit "Failed to update submodules."
    echo "Configure the build environment..."
    ./build.sh || error_exit "./build.sh failed"
    ./configure || error_exit "./configure failed"
    make || error_exit "make failed"
    echo "After the make command finished without errors, install the binary..."
    make install || error_exit "make install failed"


# Compile ModSecurity Nginx connector
compile_nginx_connector() {
    echo "[Info] Compiling ModSecurity Nginx connector..."
    echo "Download and Compile ModSecurity v3 Nginx Connector Source Code..."
    git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git /usr/local/src/ModSecurity-nginx/ || error_exit "Failed to clone ModSecurity Nginx connector."
    cd /usr/local/src/nginx/nginx-$VERSION_NUMBER/ || error_exit "Failed to navigate to Nginx source directory."
    apt build-dep nginx || error_exit "Install build dependencies for Nginx failed."
    ./configure --with-compat --add-dynamic-module=/usr/local/src/ModSecurity-nginx || error_exit "Failed to configure Nginx for ModSecurity."
    make modules || error_exit "Failed to build ModSecurity Nginx module."
    cp objs/ngx_http_modsecurity_module.so /usr/share/nginx/modules/ || error_exit "Failed to copy ModSecurity module."
}


# Configure Nginx for ModSecurity
load_connector_module() {
    echo "[Info] Configuring Nginx..."
    echo "Load the ModSecurity v3 Nginx Connector Module..."
    #sudo mkdir -p /etc/nginx/modsec || error_exit "Failed to create ModSecurity configuration directory."
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

echo "Edit the main Nginx configuration file..."
# todo Add the following line at the beginning of the file.

#load_module modules/ngx_http_modsecurity_module.so;
#Also, add the following two lines in the http {...} section, so ModSecurity will be enabled for all Nginx virtual hosts.

#modsecurity on;
#modsecurity_rules_file /etc/nginx/modsec/main.conf;

echo "create the /etc/nginx/modsec/ directory to store ModSecurity configuration..."
mkdir /etc/nginx/modsec/

echo "Then copy the ModSecurity configuration file..."
cp /usr/local/src/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf

echo "Edit the file..."
nano /etc/nginx/modsec/modsecurity.conf

# TODO Find the following line.

#SecRuleEngine DetectionOnly
#This config tells ModSecurity to log HTTP transactions, but takes no action when an attack is detected. Change it to the following, so ModSecurity will detect and block web attacks.
#SecRuleEngine On
#Then find the following line (line 224), which tells ModSecurity what information should be included in the audit log.

#SecAuditLogParts ABIJDEFHZ
#However, the default setting is wrong. You will know why later when I explain how to understand ModSecurity logs. The setting should be changed to the following.

#SecAuditLogParts ABCEFHJKZ

#If you have a coding website, you might want to disable response body inspection, otherwise, you might get 403 forbidden errors just by loading a web page with lots of code content.

#SecResponseBodyAccess Off

echo "create the /etc/nginx/modsec/main.conf file..."
nano /etc/nginx/modsec/main.conf
echo Include /etc/nginx/modsec/modsecurity.conf >> /etc/nginx/modsec/main.conf

echo "We also need to copy the Unicode mapping file."
cp /usr/local/src/ModSecurity/unicode.mapping /etc/nginx/modsec/

echo "test Nginx configuration..."
nginx -t

echo "If the test is successful, restart Nginx..."
systemctl restart nginx







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
    install_nginx
    download_source
    install_libmodsecurity
    compile_nginx_connector
    load_connector_module
    setup_owasp_crs
    echo "[Success] ModSecurity with Nginx has been successfully set up."
}

main

# credit that to https://www.linuxbabe.com/security/modsecurity-nginx-debian-ubuntu for the amazing instructions!
