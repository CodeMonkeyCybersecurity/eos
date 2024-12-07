#!/usr/bin/env python3

import subprocess
import os
import sys
import shutil
import re
import logging
import requests
import pwd

def check_sudo():
    if os.geteuid() != 0:
        error_exit("This script must be run as root or with sudo privileges.")        
    logging.info("Sudo privileges verified.")

logging.basicConfig(
    level=logging.DEBUG,  # Set default log level to INFO
    format="%(asctime)s [%(levelname)s] %(message)s",  # Format: timestamp, log level, and message
    handlers=[
        logging.StreamHandler(),  # Log to console
        logging.FileHandler("script.log", mode="a"),  # Log to file
    ]
)

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


# Download and enable OWASP CRS
def setup_owasp_crs():
    """Download and enable OWASP CRS"""
    modsec_main = "/etc/nginx/modsec/main.conf"
    modsec_etc_dir = "/etc/nginx/modsec"
    logging.info("[Info] Setting up OWASP Core Rule Set...")
    latest_release = get_latest_crs_version()
    if not latest_release:
        error_exit("Failed to determine the latest OWASP CRS version.")

    logging.info(f"Latest OWASP CRS version detected: {latest_release}")

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
            logging.info(f"Temporary file {archive_file} has been removed.")
        
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
    setup_owasp_crs()
    setup_owasp_crs()
    print("[Success]ModSecurity with the OWASP Core Rule Set (CRS) has been set up.")

if __name__ == "__main__":
    main()
