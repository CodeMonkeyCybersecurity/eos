#!/usr/bin/env python3

import subprocess
import os
import sys
import shutil
import re
import logging

print("Credit that to https://www.linuxbabe.com/security/modsecurity-nginx-debian-ubuntu for the amazing instructions which this script is based on")

logging.basicConfig(
    level=logging.DEBUG,  # Set default log level to INFO
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

def add_official_deb_src():
    """
    Add official Ubuntu deb-src entries to a .sources file, ensuring no duplicates.
    """
    sources_file = "/etc/apt/sources.list.d/ubuntu.sources"
    official_deb_src = [
        "Types: deb-src",
        "URIs: http://archive.ubuntu.com/ubuntu/",
        "Suites: noble noble-updates noble-backports",
        "Components: main restricted universe multiverse",
        "",
        "Types: deb-src",
        "URIs: http://security.ubuntu.com/ubuntu/",
        "Suites: noble-security",
        "Components: main restricted universe multiverse",
        "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg"
    ]
    try:
        if not os.path.exists(sources_file):
            raise FileNotFoundError(f"{sources_file} does not exist.")

        # Read existing content
        with open(sources_file, "r") as file:
            existing_content = file.read()

        # Check if any of the lines in official_deb_src already exist
        if any(entry in existing_content for entry in official_deb_src):
            logging.info("Official deb-src entries already exist. Skipping addition.")
            return

        # Append entries if they don't exist
        with open(sources_file, "a") as file:
            logging.info("Adding official deb-src entries to sources.list.")
            file.write("\n" + "\n".join(official_deb_src) + "\n")
        logging.info("Official deb-src entries added successfully.")

        # Update package list
        subprocess.run("apt update", shell=True, check=True)
    except Exception as e:
        logging.error(f"Failed to add official deb-src entries: {e}")
        raise
        
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
    logging.info("Nginx source files downloaded successfully.") 
    return version_number
    
def install_libmodsecurity():
    """Installing libmodsecurity..."""
    modsec_dir = "/usr/local/src/ModSecurity"

    if os.path.exists(modsec_dir):
        logging.warning(f"Directory '{modsec_dir}' already exists.")
        try:
            choice = input(f"The directory '{modsec_dir}' already exists. Do you want to overwrite it? (y/n): ").strip().lower()
            if choice == 'y':
                shutil.rmtree(modsec_dir)
                logging.info(f"Removed existing directory: {modsec_dir}")
            elif choice == 'n':
                logging.info("Skipping cloning ModSecurity.")
                return
            else:
                logging.info("Exiting as per user request.")
                sys.exit(0)
        except Exception as e:
            error_exit(f"Error handling directory '{modsec_dir}': {e}")

    run_command(
        "git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity /usr/local/src/ModSecurity/",
        "Failed to clone ModSecurity."
    )
    logging.info("ModSecurity cloned successfully.")
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
    """Compile ModSecurity Nginx connector."""
    modsec_nginx_dir = "/usr/local/src/ModSecurity-nginx/"
    try:
        # Handle existing directory
        if os.path.exists(modsec_nginx_dir):
            choice = input(f"The directory '{modsec_nginx_dir}' already exists. Do you want to overwrite it? (y/n): ").strip().lower()
            if choice == 'y':
                shutil.rmtree(modsec_nginx_dir)
                logging.info(f"Removed existing directory: {modsec_nginx_dir}")
            elif choice == 'n':
                logging.info("Skipping cloning ModSecurity Nginx connector.")
                return
            else:
                logging.info("Invalid input. Exiting.")
                sys.exit(0)

        # Clone the repository
        run_command(
            "git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git /usr/local/src/ModSecurity-nginx/",
            "Failed to clone ModSecurity Nginx connector."
        )

        # Compile and copy the module
        nginx_src_dir = f"/usr/local/src/nginx/nginx-{version_number}/"
        os.makedirs(nginx_src_dir, exist_ok=True)
        os.chdir(nginx_src_dir)
        run_command("apt build-dep nginx -y", "Failed to install build dependencies for Nginx.")
        run_command("./configure --with-compat --add-dynamic-module=/usr/local/src/ModSecurity-nginx",
                    "Failed to configure Nginx for ModSecurity.")
        run_command("make modules", "Failed to build ModSecurity Nginx module.")
        run_command("mkdir -p /usr/share/nginx/modules", "Failed to create /usr/share/nginx/modules")
        run_command("cp objs/ngx_http_modsecurity_module.so /usr/share/nginx/modules/",
                    "Failed to copy ModSecurity module.")
        logging.info("ModSecurity Nginx module compiled and installed successfully.")
    except Exception as e:
        logging.error(f"Failed to compile ModSecurity Nginx connector: {e}")
        raise

# Configure Nginx for ModSecurity
def load_connector_module():
    """Configuring Nginx for ModSecurity..."""
    nginx_conf = "/etc/nginx/nginx.conf"
    module_line = "load_module modules/ngx_http_modsecurity_module.so;"
    modsec_etc_dir = "/etc/nginx/modsec"
    
    # Backup Nginx configuration
    if os.path.exists(nginx_conf):
        shutil.copy(nginx_conf, f"{nginx_conf}.bak")
        print(f"Backup of {nginx_conf} created at {nginx_conf}.bak")
    else:
        error_exit(f"Nginx configuration file not found at {nginx_conf}.")

    # Add the module line outside any blocks
    with open(nginx_conf, "r") as file:
        content = file.readlines()

    if module_line not in content:
        with open(nginx_conf, "w") as file:
            # Write the `load_module` line first, followed by the original content
            file.write(module_line + "\n")
            file.writelines(content)
            print(f"Added '{module_line}' to {nginx_conf}.")
    
    # Ensure ModSecurity directives are present in the `http` block
    with open(nginx_conf, "r") as file:
        content = file.read()

    if "include /etc/nginx/modsec/main.conf;" not in content:
        # Insert the include directive into the http block
        content = re.sub(r'(http\s*{)', r'\1\n    include /etc/nginx/modsec/main.conf;', content, flags=re.MULTILINE)

        with open(nginx_conf, "w") as file:
            file.write(content)
        print("Included ModSecurity configuration in nginx.conf.")

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

    archive_file = f"v{latest_release}.tar.gz"
    extracted_dir = f"coreruleset-{latest_release}"

    try:
        # Download the OWASP CRS archive
        run_command(f"wget https://github.com/coreruleset/coreruleset/archive/v{latest_release}.tar.gz", "Failed to download OWASP CRS.")
        
        # Extract the archive
        run_command(f"tar xvf {archive_file}", "Failed to extract OWASP CRS.")
        
        # Verify the extracted directory exists
        if not os.path.exists(extracted_dir):
            error_exit(f"Extracted directory {extracted_dir} not found.")

        # Move the extracted directory to the desired location
        if os.path.exists(os.path.join(modsec_etc_dir, extracted_dir)):
            shutil.rmtree(os.path.join(modsec_etc_dir, extracted_dir))
        shutil.move(extracted_dir, modsec_etc_dir)

        # Rename the configuration file
        crs_conf = os.path.join(modsec_etc_dir, "crs-setup.conf")
        if os.path.exists(f"{crs_conf}.example"):
            shutil.move(f"{crs_conf}.example", crs_conf)
        else:
            error_exit(f"Failed to find {crs_conf}.example for renaming.")
        
        # Include CRS rules in the main configuration
        with open(modsec_main, "a") as file:
            file.write(f"Include {crs_conf}\n")
            file.write(f"Include {os.path.join(modsec_etc_dir, 'rules', '*.conf')}\n")

        # Clean up the downloaded archive
        if os.path.exists(archive_file):
            os.remove(archive_file)
            print(f"Temporary file {archive_file} has been removed.")
        
        # Test and restart Nginx
        run_command("nginx -t", "Nginx configuration test failed.")
        run_command("systemctl restart nginx", "Failed to restart Nginx.")

        logging.info("OWASP CRS setup completed successfully.")
    
    except Exception as e:
        logging.error(f"Failed to set up OWASP CRS: {e}")
        raise

# Main function
def main():
    logging.info("Starting the script...")
    check_sudo()
    check_dependencies()
    add_official_deb_src()
    install_nginx()
    version_number = download_source()
    install_libmodsecurity()
    compile_nginx_connector(version_number)
    load_connector_module()
    setup_owasp_crs()
    logging.info("[Success] ModSecurity with Nginx has been successfully set up.")

if __name__ == "__main__":
    main()
