#!/usr/bin/env python3

import subprocess
import os
import sys
import shutil
import re
import logging

print("Credit that to https://www.linuxbabe.com/security/modsecurity-nginx-debian-ubuntu for the amazing instructions which this script is based on")

logging.basicConfig(
    level=logging.INFO,  # Set default log level to INFO
    format="%(asctime)s [%(levelname)s] %(message)s",  # Format: timestamp, log level, and message
    handlers=[
        logging.StreamHandler(),  # Log to console
        logging.FileHandler("script.log", mode="a"),  # Log to file
    ]
)

def error_exit(message):
    logging.error(message)
    sys.exit(1)

def check_sudo():
    if os.geteuid() != 0:
        error_exit("This script must be run as root or with sudo privileges.")        
    logging.info("Sudo privileges verified.")

def get_valid_user(prompt):
    while True:
        user_input = input(prompt).strip()
        if not user_input:
            print("[Error] Input cannot be empty. Please try again.")
        elif not user_input.isalnum():
            print("[Error] Usernames can only contain letters and numbers. Please try again.")
        else:
            return user_input

def get_valid_version(prompt):
    version_pattern = r'^\d+\.\d+\.\d+$'  # Example: 1.24.0
    while True:
        user_input = input(prompt).strip()
        if re.match(version_pattern, user_input):
            return user_input
        print("[Error] Invalid version format. Expected X.Y.Z (e.g., 4.9.0). Please try again.")
        
def command_exists(command):
    """Check if a command exists in the system's PATH."""
    return shutil.which(command) is not None

def check_dependencies():
    required_commands = ["apt", "nginx", "wget", "git"]
    missing_commands = [cmd for cmd in required_commands if not command_exists(cmd)]
    if missing_commands:
        error_exit(f"The following commands are required but not installed: {', '.join(missing_commands)}.\n"
                   f"Please install them using 'sudo apt install {' '.join(missing_commands)}'.")
    
def run_command(command, error_message):
    logging.debug(f"Running command: {command}")
    # Run the command interactively
    result = subprocess.run(command, shell=True)
    if result.returncode != 0:
        logging.error(f"Command failed.")
        error_exit(f"{error_message}")
    logging.debug("Command succeeded.")

def enable_deb_src():
    """Ensure that deb-src entries are enabled in sources.list."""
    sources_file = "/etc/apt/sources.list"
    try:
        with open(sources_file, "r") as file:
            lines = file.readlines()

        updated_lines = []
        for line in lines:
            if line.strip().startswith("# deb-src"):
                updated_lines.append(line.lstrip("# "))  # Uncomment deb-src lines
            else:
                updated_lines.append(line)

        with open(sources_file, "w") as file:
            file.writelines(updated_lines)

        logging.info("deb-src entries enabled in sources.list. Updating package lists...")
        run_command("apt update", "Failed to update package lists after enabling deb-src.")
    except Exception as e:
        error_exit(f"Failed to enable deb-src entries: {e}")

def install_nginx():
    """Install and configure Nginx on the system."""
    run_command("apt update", "Failed to update package list.")
    run_command("apt install -y nginx", "Failed to install nginx.")
    run_command("nginx -V", "Failed to verify nginx version.")
    run_command("apt install -y software-properties-common", "Failed to install software-properties-common.")
    run_command("apt-add-repository -ss", "Failed to add repository.")
    run_command("apt update", "Failed to update package list after adding repository.")

def download_source():
    """Downloading and configuring Nginx source files"""
    logging.info("Starting to download Nginx source files...")

    input_user = get_valid_user("Which user would you like to administer nginx?: ")
    
    run_command(f"chown {input_user}:{input_user} /usr/local/src/ -R", f"Failed to change ownership of /usr/local/src/ to {input_user}.")
    os.makedirs("/usr/local/src/nginx", exist_ok=True)
    try:
        os.chdir("/usr/local/src/nginx")
    except FileNotFoundError:
        error_exit("Failed to change directory to /usr/local/src/nginx.")
    
    print("Downloading Nginx source package...")
    run_command("apt install -y dpkg-dev", "Failed to install dpkg-dev.")
    run_command("apt source nginx", "Failed to download nginx source.")
    print("Listing downloaded source files:")
    subprocess.run(["ls", "-lah", "/usr/local/src/nginx/"])
    version_number = get_valid_version("Enter nginx version number (e.g., 1.24.0): ")
    return version_number
    logging.info("Nginx source files downloaded successfully.")

def install_libmodsecurity():
    """Installing libmodsecurity..."""
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
    """Compiling ModSecurity Nginx connector..."""
    run_command("git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git /usr/local/src/ModSecurity-nginx/", "Failed to clone ModSecurity Nginx connector.")
    os.makedirs(f"/usr/local/src/nginx/nginx-{version_number}/", exist_ok=True)
    os.chdir(f"/usr/local/src/nginx/nginx-{version_number}/")
    run_command("apt build-dep nginx -y", "Failed to install build dependencies for Nginx.")
    run_command(f"./configure --with-compat --add-dynamic-module=/usr/local/src/ModSecurity-nginx", "Failed to configure Nginx for ModSecurity.")
    run_command("make modules", "Failed to build ModSecurity Nginx module.")
    run_command("cp objs/ngx_http_modsecurity_module.so /usr/share/nginx/modules/", "Failed to copy ModSecurity module.")
    
# Configure Nginx for ModSecurity
def load_connector_module():
    """Configuring Nginx for ModSecurity..."""
    nginx_conf = "/etc/nginx/nginx.conf"
    module_line = "load_module modules/ngx_http_modsecurity_module.so;"
    
    # Backup Nginx configuration
    if os.path.exists(nginx_conf):
        shutil.copy(nginx_conf, f"{nginx_conf}.bak")
        print(f"Backup of {nginx_conf} created at {nginx_conf}.bak")
    else:
        error_exit(f"Nginx configuration file not found at {nginx_conf}.")

    # Add the module line if not already present
    with open(nginx_conf, "r+") as file:
        content = file.read()
        if module_line not in content:
            file.seek(0, 0)
            file.write(f"{module_line}\n{content}")
            print(f"Added '{module_line}' to the beginning of {nginx_conf}.")
    
    # Ensure ModSecurity directives are present in the `http` block
    modsec_etc_dir = "/etc/nginx/modsec"
    os.makedirs(modsec_etc_dir, exist_ok=True)
    shutil.copy("/usr/local/src/ModSecurity/modsecurity.conf-recommended", f"{modsec_etc_dir}/modsecurity.conf")
    shutil.copy("/usr/local/src/ModSecurity/unicode.mapping", modsec_etc_dir)

    # Update ModSecurity configuration
    modsec_conf = f"{modsec_etc_dir}/modsecurity.conf"
    shutil.copy(modsec_conf, f"{modsec_conf}.bak")
    print(f"Backup of {modsec_conf} saved at {modsec_conf}.bak")
    with open(modsec_conf, "r") as file:
        config_lines = file.readlines()
    with open(modsec_conf, "w") as file:
        for line in config_lines:
            if "SecAuditLogParts" in line:
                line = line.replace("ABIJDEFHZ", "ABCEFHJKZ")
            if "SecResponseBodyAccess On" in line:
                line = line.replace("SecResponseBodyAccess On", "SecResponseBodyAccess Off")
            file.write(line)
    print("ModSecurity configuration updated.")

    # Test Nginx configuration and restart
    run_command("nginx -t", "Nginx configuration test failed.")
    run_command("systemctl restart nginx", "Failed to restart Nginx.")
    
# Download and enable OWASP CRS
def setup_owasp_crs():
    """Download and enable OWASP CRS"""
    modsec_main = "/etc/nginx/modsec/main.conf"
    modsec_etc_dir = "/etc/nginx/modsec"
    print("[Info] Setting up OWASP Core Rule Set...")
    print("Navigate to 'https://github.com/coreruleset/coreruleset/releases' in your browser and find the latest release (e.g., 4.9.0).")
    latest_release = get_valid_version("Enter the latest release (e.g., 4.9.0): ")

    run_command(f"wget https://github.com/coreruleset/coreruleset/archive/v{latest_release}.tar.gz", "Failed to download OWASP CRS.")
    run_command(f"tar xvf v{latest_release}.tar.gz", "Failed to extract OWASP CRS.")

    extracted_dir = f"coreruleset-{latest_release}"
    if not os.path.exists(extracted_dir):
        error_exit(f"Extracted directory {extracted_dir} not found.")
    
    if os.path.exists(os.path.join(modsec_etc_dir, extracted_dir)):
        shutil.rmtree(os.path.join(modsec_etc_dir, extracted_dir))
    shutil.move(extracted_dir, modsec_etc_dir)    
    crs_conf = os.path.join(modsec_etc_dir, "crs-setup.conf")
    if os.path.exists(f"{crs_conf}.example"):
        shutil.move(f"{crs_conf}.example", crs_conf)
    else:
        error_exit(f"Failed to find {crs_conf}.example for renaming.")
    
    with open(modsec_main, "a") as file:
        file.write(f"Include {crs_conf}\n")
        file.write(f"Include {os.path.join(modsec_etc_dir, 'rules', '*.conf')}\n")

    run_command("nginx -t", "Nginx configuration test failed.")
    run_command("systemctl restart nginx", "Failed to restart Nginx.")


# Main function
def main():
    logging.info("Starting the script...")
    check_sudo()
    check_dependencies()
    enable_deb_src()
    install_nginx()
    version_number = download_source()
    install_libmodsecurity()
    compile_nginx_connector(version_number)
    load_connector_module()
    setup_owasp_crs()
    logging.info("[Success] ModSecurity with Nginx has been successfully set up.")

if __name__ == "__main__":
    main()
