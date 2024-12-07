def get_nginx_version(nginx_source_dir):
    """Automatically get the Nginx version from the source directory name."""
    dirs = os.listdir(nginx_source_dir)
    version_pattern = re.compile(r'nginx-(\d+\.\d+\.\d+)')
    for dir_name in dirs:
        match = version_pattern.match(dir_name)
        if match:
            return match.group(1)
    return None
