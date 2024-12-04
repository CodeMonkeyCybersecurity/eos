def get_ubuntu_codename():
    try:
        codename = subprocess.check_output(['lsb_release', '-sc']).decode().strip()
        return codename
    except Exception as e:
        print(f"Error determining Ubuntu codename: {e}")
        return None
