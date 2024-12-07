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
