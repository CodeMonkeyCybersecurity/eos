#!/usr/bin/env python3

import subprocess
import os
import sys
import shutil
import re
import logging
import requests
import pwd

logging.info("Credit that to https://www.linuxbabe.com/security/modsecurity-nginx-debian-ubuntu for the amazing instructions which this script is based on")

logging.basicConfig(
    level=logging.DEBUG,  # Set default log level to INFO
    format="%(asctime)s [%(levelname)s] %(message)s",  # Format: timestamp, log level, and message
    handlers=[
        logging.StreamHandler(),  # Log to console
        logging.FileHandler("script.log", mode="a"),  # Log to file
    ]
)
def check_sudo():
    if os.geteuid() != 0:
        error_exit("This script must be run as root or with sudo privileges.")        
    logging.info("Sudo privileges verified.")
    
def error_exit(message):
    logging.error(message)
    sys.exit(1)

def get_valid_user(prompt):
    while True:
        user_input = input(prompt).strip()
        if not user_input:
            logging.error("[Error] Input cannot be empty. Please try again.")
        elif not user_input.isalnum():
            logging.error("[Error] Usernames can only contain letters and numbers. Please try again.")
        else:
            return user_input

def get_ubuntu_codename():
    """Get the Ubuntu codename (e.g., focal, jammy)."""
    try:
        result = subprocess.run(['lsb_release', '-sc'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            error_exit("Failed to get Ubuntu codename.")
        codename = result.stdout.strip()
        logging.info(f"Ubuntu codename detected: {codename}")
        return codename
    except Exception as e:
        logging.error(f"Failed to get Ubuntu codename: {e}")
        error_exit("Failed to get Ubuntu codename.")

def prepare_deb_src_entries(ubuntu_codename):
    entries = [
        "Types: deb-src",
        "URIs: http://archive.ubuntu.com/ubuntu/",
        f"Suites: {ubuntu_codename} {ubuntu_codename}-updates {ubuntu_codename}-backports",
        "Components: main restricted universe multiverse",
        "",
        "Types: deb-src",
        "URIs: http://security.ubuntu.com/ubuntu/",
        f"Suites: {ubuntu_codename}-security",
        "Components: main restricted universe multiverse",
        "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg"
    ]
    return "\n".join(entries)

def get_nginx_version(nginx_source_dir):
    """Automatically get the Nginx version from the source directory name."""
    dirs = os.listdir(nginx_source_dir)
    version_pattern = re.compile(r'nginx-(\d+\.\d+\.\d+)')
    for dir_name in dirs:
        match = version_pattern.match(dir_name)
        if match:
            return match.group(1)
    return None

def command_exists(command):
    """Check if a command exists in the system's PATH."""
    return shutil.which(command) is not None

def check_dependencies():
    required_commands = ["apt", "wget", "git"]
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
    Add official Ubuntu deb-src entries to /etc/apt/sources.list.d/ubuntu.sources, ensuring no duplicates.
    """
    ubuntu_codename = get_ubuntu_codename()
    sources_file = "/etc/apt/sources.list.d/ubuntu.sources"
    deb_src_content = prepare_deb_src_entries(ubuntu_codename)

    try:
        # Read existing content if the file exists
        if os.path.exists(sources_file):
            with open(sources_file, "r") as file:
                existing_content = file.read()
        else:
            existing_content = ""
            # Ensure the directory exists
            os.makedirs(os.path.dirname(sources_file), exist_ok=True)
            logging.info(f"Created directory {os.path.dirname(sources_file)} for sources file.")

        # Check if the deb-src entries are already present
        if deb_src_content in existing_content:
            logging.info("deb-src entries already exist in ubuntu.sources. Skipping addition.")
            return

        # Append deb-src entries to the file
        with open(sources_file, "a") as file:
            logging.info("Adding deb-src entries to ubuntu.sources.")
            # Add a separator if the file is not empty
            if existing_content.strip():
                file.write("\n\n")
            file.write(deb_src_content + "\n")
        logging.info("deb-src entries added successfully.")

        # Update package list
        run_command("apt update", "Failed to update package list.")
    except Exception as e:
        logging.error(f"Failed to add deb-src entries: {e}")
        raise

def get_latest_crs_version():
    """Fetch the latest CRS version from GitHub releases."""
    try:
        response = requests.get("https://api.github.com/repos/coreruleset/coreruleset/releases/latest")
        data = response.json()
        latest_version = data['tag_name'].lstrip('v')
        return latest_version
    except Exception as e:
        logging.error(f"Failed to fetch latest CRS version: {e}")
        return None

def check_and_create_directory(dir_path):
    """Ensure that the specified path is a directory. If it exists, handle according to user choice."""
    if os.path.islink(dir_path):
        os.unlink(dir_path)
        logging.info(f"Removed symlink at '{dir_path}'.")

    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
        logging.info(f"Directory '{dir_path}' has been created.")
    elif os.path.isdir(dir_path):
        print(f"Directory '{dir_path}' already exists.")
        print("Options:")
        print("1. Skip and continue (default)")
        print("2. Overwrite the existing directory")
        print("3. Exit the script")

        choice = input("Please enter your choice [1/2/3]: ").strip() or '1'

        if choice == '1':
            logging.info("Continuing with the existing directory.")
        elif choice == '2':
            try:
                shutil.rmtree(dir_path)
                os.makedirs(dir_path)
                logging.info(f"Directory '{dir_path}' has been overwritten.")
            except Exception as e:
                logging.error(f"Failed to overwrite directory '{dir_path}': {e}")
                sys.exit(1)
        elif choice == '3':
            logging.info("Exiting script.")
            sys.exit(0)
        else:
            logging.warning("Invalid choice. Continuing with the existing directory.")
    else:
        # Path exists but is not a directory
        logging.error(f"A file with the name '{dir_path}' exists.")
        logging.error("Cannot proceed as a file exists with the same name as the desired directory.")
        sys.exit(1)
        
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

    # Detect the current user or default to 'root'
    try:
        if os.geteuid() == 0 and 'SUDO_USER' in os.environ:
            input_user = os.environ['SUDO_USER']
        else:
            input_user = pwd.getpwuid(os.geteuid()).pw_name
    except Exception as e:
        logging.error(f"Failed to detect the current user: {e}")
        input_user = 'root'

    logging.info(f"Detected user: {input_user}")
    
    # Proceed without user input
    if input_user != 'root':
        run_command(f"chown {input_user}:{input_user} /usr/local/src/ -R", f"Failed to change ownership of /usr/local/src/ to {input_user}.")
    
    os.makedirs("/usr/local/src/nginx", exist_ok=True)
    try:
        os.chdir("/usr/local/src/nginx")
    except FileNotFoundError:
        error_exit("Failed to change directory to /usr/local/src/nginx.")
    
    logging.info("Downloading Nginx source package...")
    run_command("apt install -y dpkg-dev", "Failed to install dpkg-dev.")
    run_command("apt source nginx", "Failed to download nginx source.")
    logging.info("Listing downloaded source files:")
    subprocess.run(["ls", "-lah", "/usr/local/src/nginx/"])
    logging.info("Nginx source files downloaded successfully.") 

    # Get the Nginx version number
    version_number = get_nginx_version("/usr/local/src/nginx/")
    if not version_number:
        error_exit("Failed to determine Nginx version.")
    logging.info(f"Nginx version {version_number} detected.")
    return version_number
    
def install_libmodsecurity():
    """Installing libmodsecurity..."""
    modsec_dir = "/usr/local/src/ModSecurity"
    check_and_create_directory(modsec_dir)

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

def compile_nginx_connector(version_number):
    """Compile ModSecurity Nginx connector."""
    nginx_source_parent_dir = '/usr/local/src/nginx/'
    logging.info(f"Using Nginx version: {version_number}") 
    
    modsec_nginx_dir = "/usr/local/src/ModSecurity-nginx"
    nginx_src_dir = f"/usr/local/src/nginx/nginx-{version_number}/"
    nginx_modules_dir = "/usr/share/nginx/modules/"

    try:
        # Prepare directories
        check_and_create_directory(modsec_nginx_dir)
        check_and_create_directory(nginx_modules_dir)

        # Clone the repository
        run_command(
            f"git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git {modsec_nginx_dir}",
            "Failed to clone ModSecurity Nginx connector."
        )

        # Compile and copy the module
        os.chdir(nginx_src_dir)
        run_command("apt build-dep nginx -y", "Failed to install build dependencies for Nginx.")
        run_command(
            f"./configure --with-compat --with-openssl=/usr/include/openssl/ --add-dynamic-module={modsec_nginx_dir}",
            "Failed to configure Nginx for ModSecurity."
        )
        run_command("make modules", "Failed to build ModSecurity Nginx module.")

        ngx_module_path = os.path.join(nginx_src_dir, 'objs', 'ngx_http_modsecurity_module.so')
        run_command(
            f"cp {ngx_module_path} {nginx_modules_dir}",
            "Failed to copy ModSecurity module."
        )
        logging.info("ModSecurity Nginx module compiled and installed successfully.")

    except Exception as e:
        logging.error(f"Failed to compile ModSecurity Nginx connector: {e}")
        raise

# Configure Nginx for ModSecurity
def load_connector_module():
    """Configuring Nginx for ModSecurity..."""
    nginx_conf = "/etc/nginx/nginx.conf"
    module_line = "load_module modules/ngx_http_modsecurity_module.so;"
    modsec_on_line = "modsecurity on;"
    modsec_rules_file_line = "modsecurity_rules_file /etc/nginx/modsec/main.conf;"
    modsec_etc_dir = "/etc/nginx/modsec"
    modsec_main_conf = os.path.join(modsec_etc_dir, "main.conf")

    # Backup Nginx configuration
    if os.path.exists(nginx_conf):
        # Create a backup only if one doesn't already exist
        backup_conf = f"{nginx_conf}.bak"
        if not os.path.exists(backup_conf):
            shutil.copy(nginx_conf, backup_conf)
            logging.info(f"Backup of {nginx_conf} created at {backup_conf}")
    else:
        error_exit(f"Nginx configuration file not found at {nginx_conf}.")

    # Read existing content
    with open(nginx_conf, "r") as file:
        content = file.read()

    # Check if module line already exists
    if module_line not in content:
        # Add the module line at the very beginning
        content = module_line + "\n" + content
        logging.info(f"Added '{module_line}' to {nginx_conf}.")
    else:
        logging.info(f"Module line already exists in {nginx_conf}, skipping addition.")

    # Prepare the ModSecurity directives
    modsec_directives = f"\n    {modsec_on_line}\n    {modsec_rules_file_line}\n"

    # Check if ModSecurity directives already exist in the http block
    http_block_pattern = re.compile(r'(http\s*{)(.*?)(\n})', re.DOTALL)
    match = http_block_pattern.search(content)
    if match:
        http_block_start = match.start(2)
        http_block_end = match.end(2)
        http_block_content = match.group(2)
        if modsec_on_line in http_block_content and modsec_rules_file_line in http_block_content:
            logging.info("ModSecurity directives already present in http block, skipping addition.")
        else:
            # Insert ModSecurity directives into the http block
            new_http_block_content = http_block_content + modsec_directives
            content = content[:http_block_start] + new_http_block_content + content[http_block_end:]
            logging.info("Added ModSecurity directives to http block.")
    else:
        logging.error("Could not find http block in nginx.conf.")
        error_exit("Failed to insert ModSecurity directives into nginx.conf.")

    # Write the updated content back to the file
    with open(nginx_conf, "w") as file:
        file.write(content)

    # Ensure ModSecurity directory exists
    check_and_create_directory(modsec_etc_dir)

    # Copy default ModSecurity configuration file
    modsec_conf_src_rec = "/usr/local/src/ModSecurity/modsecurity.conf-recommended"
    modsec_conf_dst = os.path.join(modsec_etc_dir, "modsecurity.conf")
    if not os.path.exists(modsec_conf_dst):
        if os.path.exists(modsec_conf_src_rec):
            shutil.copy(modsec_conf_src_rec, modsec_conf_dst)
            logging.info(f"Copied ModSecurity configuration to {modsec_conf_dst}")
        else:
            error_exit(f"ModSecurity configuration file not found at {modsec_conf_src_rec}.")
    else:
        logging.info(f"ModSecurity configuration already exists at {modsec_conf_dst}, skipping copy.")

    # Create main.conf if it doesn't exist
    if not os.path.exists(modsec_main_conf):
        with open(modsec_main_conf, "w") as file:
            file.write(f"Include {modsec_conf_dst}\n")
            file.write(f"SecRuleEngine On\n")
        logging.info("ModSecurity main configuration created.")
    else:
        logging.info("ModSecurity main configuration already exists, skipping creation.")

    # Test Nginx configuration and restart
    run_command("nginx -t", "Nginx configuration test failed.")
    run_command("systemctl restart nginx", "Failed to restart Nginx.")
    
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
    print("[Success] ModSecurity with Nginx has been successfully set up.")
    print("You should now download and enable the OWASP Core Rule Set.")
    print("The OWASP Core Rule Set (CRS) is the standard rule set used with ModSecurity.")
    print("The SetupOwaspCrs.py script can do this.")

if __name__ == "__main__":
    main()
