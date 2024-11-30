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
    chown "$INPUT_USER:$INPUT_USER" /usr/local/src/ -R || error_exit "chown '$INPUT_USER:$INPUT_USER' /usr/local/src/ -R failed"
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
    # Define the Nginx configuration file path
    NGINX_CONF="/etc/nginx/nginx.conf"
    MODULE_LINE="load_module modules/ngx_http_modsecurity_module.so;"
    MODSEC_LINES=(
        "modsecurity on;"
        "modsecurity_rules_file /etc/nginx/modsec/main.conf;"
    )
    # Backup the existing Nginx configuration file
    if [[ -f "$NGINX_CONF" ]]; then
        cp "$NGINX_CONF" "${NGINX_CONF}.bak"
        echo "Backup of $NGINX_CONF created at ${NGINX_CONF}.bak"
    else
        echo "Nginx configuration file not found at $NGINX_CONF. Exiting."
        exit 1
    fi
    # Check if the module line already exists
    if grep -q "^$MODULE_LINE" "$NGINX_CONF"; then
        echo "The module line is already present in the configuration file. No changes made."
    else
        # Insert the line at the beginning of the file
        sed -i "1s|^|$MODULE_LINE\n|" "$NGINX_CONF"
        echo "Added '$MODULE_LINE' to the beginning of $NGINX_CONF."
    fi
    # Add ModSecurity lines to the http { ... } section
    if grep -q "http {" "$NGINX_CONF"; then
        for LINE in "${MODSEC_LINES[@]}"; do
            if ! grep -q "^$LINE" "$NGINX_CONF"; then
                sed -i "/http {/a \    $LINE" "$NGINX_CONF"
                echo "Added '$LINE' to the http { ... } section."
            else
                echo "'$LINE' is already present in the http { ... } section. No changes made."
            fi
        done
    else
        echo "No http { ... } section found in $NGINX_CONF. Please check the configuration file."
        exit 1
    fi
    MODSEC_ETC_DIR="/etc/nginx/modsec"
    mkdir -p $MODSEC_ETC_DIR || error_exit "Failed to create ModSecurity configuration directory."
    MODSEC_LOCAL_DIR="/usr/local/src/ModSecurity"
    cp $MODSEC_LOCAL_DIR/modsecurity.conf-recommended $MODSEC_ETC_DIR/modsecurity.conf || error_exit "Failed to copy ModSecurity configuration."
    cp $MODSEC_LOCAL_DIR/unicode.mapping $MODSEC_ETC_DIR || error_exit "Failed to copy unicode mapping file."
    MODSEC_CONF="/etc/nginx/modsec/modsecurity.conf" 
    cp "$MODSEC_CONF" "${MODSEC_CONF}.bak" || error_exit "Failed to create modsec_conf.bak"
    echo "Backup of $MODSEC_CONF saved at ${MODSEC_CONF}.bak"
    sed -i 's/^SecAuditLogParts ABIJDEFHZ/SecAuditLogParts ABCEFHJKZ/' "$MODSEC_CONF" || error_exit "Failed to change default logging configs in $MODSEC_CONF"
    echo "SecAuditLogParts updated."
    echo "disabling body inspection"
    sed -i 's/^SecResponseBodyAccess On/SecAuditLogParts Off/' "$MODSEC_CONF" || error_exit "SecResponseBodyAccess failed to be turned off"
    MODSEC_MAIN="$MODSEC_ETC_DIR/main.conf"
    echo "Include $MODSEC_CONF;" | sudo tee -a $MODSEC_MAIN >/dev/null
    sudo nginx -t || error_exit "Nginx configuration test failed."
    sudo systemctl restart nginx || error_exit "Failed to restart Nginx."
}
    
# Download and enable OWASP CRS
setup_owasp_crs() {
    echo "[Info] Setting up OWASP Core Rule Set..."
    echo "Navigate in your browser to 'https://github.com/coreruleset/coreruleset/releases' and find out what the latest release it (eg. 4.9.0)"
    read -p "Enter the latest release: " LATEST_RELEASE
    wget https://github.com/coreruleset/coreruleset/archive/v$LATEST_RELEASE.tar.gz || error_exit "Failed to download OWASP CRS."
    tar xvf v$LATEST_RELEASE.tar.gz || error_exit "Failed to extract OWASP CRS."
    CORERULESET_LATEST="coreruleset-$LATEST_RELEASE"
    sudo mv $CORERULESET_LATEST $MODSEC_ETC_DIR || error_exit "Failed to move OWASP CRS."
    CORERULESET="$MODSEC_ETC_DIR/$CORERULESET_LATEST"
    CRS_CONF="$CORERULESET-$LATEST_RELEASE/crs-setup.conf"
    sudo mv $CRS_CONF.example $CRS_CONF || error_exit "Failed to rename CRS configuration."
    # Add CRS includes to main.conf
echo -e "Include $CRS_CONF\nInclude $CORERULESET/rules/*.conf" >> $MODSEC_MAIN
    MODSEC_MAIN
}

    




    
    
    
    echo "Include /etc/nginx/modsec/coreruleset-3.3.4/crs-setup.conf;" | sudo tee -a /etc/nginx/modsec/main.conf >/dev/null
    echo "Include /etc/nginx/modsec/coreruleset-3.3.4/rules/*.conf;" | sudo tee -a /etc/nginx/modsec/main.conf >/dev/null
    echo "load_module modules/ngx_http_modsecurity_module.so;" | sudo tee -a /etc/nginx/nginx.conf >/dev/null
    sudo nginx -t || error_exit "Nginx configuration test failed."
    sudo systemctl restart nginx || error_exit "Failed to restart Nginx."
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
