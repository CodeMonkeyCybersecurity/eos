def check_sudo():
    if os.geteuid() != 0:
        error_exit("This script must be run as root or with sudo privileges.")        
    logging.info("Sudo privileges verified.")
