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
