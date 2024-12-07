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
