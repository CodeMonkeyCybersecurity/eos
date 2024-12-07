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
