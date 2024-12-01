import subprocess
import os
import sys
import shutil

def error_exit(message):
    print(f"[Error] {message}", file=sys.stderr)
    sys.exit(1)

../checkSudo.sh || error_exit "Failed to verify sudo privileges."

# Function to check if a command exists
def command_exists(command):
    result = subprocess.run(["command", "-v", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0


def run_command(command, error_message):
    result = subprocess.run(command, shell=True)
    if result.returncode != 0:
        error_exit(error_message)

def install_nginx():
    run_command("apt update", "Failed to update package list.")
    run_command("apt install -y nginx", "Failed to install nginx.")
    run_command("nginx -V", "Failed to verify nginx version.")
    run_command("apt install -y software-properties-common", "Failed to install software-properties-common.")
    run_command("apt-add-repository -ss", "Failed to add repository.")
    run_command("apt update", "Failed to update package list after adding repository.")

def download_source():
    input_user = input("Which user would you like to administer nginx?: ")
    if not input_user:
        error_exit("User input is required.")
    
    run_command(f"chown {input_user}:{input_user} /usr/local/src/ -R", f"Failed to change ownership of /usr/local/src/ to {input_user}.")
    os.makedirs("/usr/local/src/nginx", exist_ok=True)
    os.chdir("/usr/local/src/nginx")
    
    print("Downloading Nginx source package...")
    run_command("apt install -y dpkg-dev", "Failed to install dpkg-dev.")
    run_command("apt source nginx", "Failed to download nginx source.")
    print("Listing downloaded source files:")
    subprocess.run(["ls", "-lah", "/usr/local/src/nginx/"])
    version_number = input("Enter nginx version number (e.g., 1.24.0): ")
    return version_number

def install_libmodsecurity():
    print("Installing libmodsecurity...")
    run_command("apt install -y git", "Failed to install git.")
    run_command("git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity /usr/local/src/ModSecurity/", "Failed to clone ModSecurity.")
    os.chdir("/usr/local/src/ModSecurity")
    run_command("apt update", "Failed to update package list.")
    run_command("apt install -y gcc make build-essential autoconf automake libtool libcurl4-openssl-dev liblua5.3-dev libpcre2-dev libfuzzy-dev ssdeep gettext pkg-config libpcre3 libpcre3-dev libxml2 libxml2-dev libcurl4 libgeoip-dev libyajl-dev doxygen uuid-dev", "Failed to install dependencies.")
    run_command("git submodule init", "Failed to initialize submodules.")
    run_command("git submodule update", "Failed to update submodules.")
    run_command("./build.sh", "Failed to build ModSecurity.")
    run_command("./configure", "Failed to configure ModSecurity.")
    run_command("make", "Failed to compile ModSecurity.")
    run_command("make install", "Failed to install ModSecurity.")


# Compile ModSecurity Nginx connector
def compile_nginx_connector(version_number):
    print("Compiling ModSecurity Nginx connector...")
    run_command("git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git /usr/local/src/ModSecurity-nginx/", "Failed to clone ModSecurity Nginx connector.")
    os.chdir(f"/usr/local/src/nginx/nginx-{version_number}/")
    run_command("apt build-dep nginx -y", "Failed to install build dependencies for Nginx.")
    run_command(f"./configure --with-compat --add-dynamic-module=/usr/local/src/ModSecurity-nginx", "Failed to configure Nginx for ModSecurity.")
    run_command("make modules", "Failed to build ModSecurity Nginx module.")
    run_command("cp objs/ngx_http_modsecurity_module.so /usr/share/nginx/modules/", "Failed to copy ModSecurity module.")




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
    sed -i 's/^SecResponseBodyAccess On/SecResponseBodyAccess Off/' "$MODSEC_CONF" || error_exit "SecResponseBodyAccess failed to be turned off"
    MODSEC_MAIN="$MODSEC_ETC_DIR/main.conf"
    echo "Include $MODSEC_CONF;" | sudo tee -a $MODSEC_MAIN >/dev/null
    # Define the NGINX configuration test command with error handling
    sudo nginx -t || { echo "Nginx configuration test failed." >&2; exit 1; }
    sudo systemctl restart nginx || { echo "Failed to restart Nginx." >&2; exit 1; }
}
    
# Download and enable OWASP CRS
setup_owasp_crs() {
    echo "[Info] Setting up OWASP Core Rule Set..."
    echo "Navigate in your browser to 'https://github.com/coreruleset/coreruleset/releases' and find out what the latest release it (eg. 4.9.0)"
    read -p "Enter the latest release: " LATEST_RELEASE
    wget https://github.com/coreruleset/coreruleset/archive/v$LATEST_RELEASE.tar.gz || error_exit "Failed to download OWASP CRS."
    tar xvf v$LATEST_RELEASE.tar.gz || error_exit "Failed to extract OWASP CRS."
    sudo mv "coreruleset-$LATEST_RELEASE/" $MODSEC_ETC_DIR || error_exit "Failed to move OWASP CRS."
    CRS_CONF="coreruleset-$LATEST_RELEASE/crs-setup.conf"
    sudo mv $CRS_CONF.example $CRS_CONF || error_exit "Failed to rename CRS configuration."
    # Add CRS includes to main.conf
    echo -e "Include $CRS_CONF\nInclude $CORERULESET/rules/*.conf" >> $MODSEC_MAIN
    sudo nginx -t || { echo "Nginx configuration test failed." >&2; exit 1; }
    sudo systemctl restart nginx || { echo "Failed to restart Nginx." >&2; exit 1; }
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
