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
