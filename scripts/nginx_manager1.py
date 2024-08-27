import os
import subprocess
import tempfile
import shutil

NGINX_CONF_DIR = '/etc/nginx/sites-available'
NGINX_SITES_ENABLED_DIR = '/etc/nginx/sites-enabled'

def create_proxy_config(domain_name, proxy_pass, config_file):
    config_content = f"""
    server {{
        listen 80;
        server_name {domain_name};

        location / {{
            proxy_pass {proxy_pass};
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }}
    }}
    """
    with open(config_file, 'w') as f:
        f.write(config_content)

def add_reverse_proxy(domain_name, proxy_pass):
    config_file = os.path.join(NGINX_CONF_DIR, domain_name)

    if os.path.exists(config_file):
        print(f"Config for {domain_name} already exists.")
        return

    create_proxy_config(domain_name, proxy_pass, config_file)

    # Enable the site
    enabled_site = os.path.join(NGINX_SITES_ENABLED_DIR, domain_name)
    os.symlink(config_file, enabled_site)
    
    # Reload Nginx
    subprocess.run(['sudo', 'nginx', '-s', 'reload'])
    print(f"Added reverse proxy for {domain_name} -> {proxy_pass}")

def remove_reverse_proxy(domain_name):
    config_file = os.path.join(NGINX_CONF_DIR, domain_name)
    enabled_site = os.path.join(NGINX_SITES_ENABLED_DIR, domain_name)

    if os.path.exists(enabled_site):
        os.remove(enabled_site)
        print(f"Removed enabled site for {domain_name}")

    if os.path.exists(config_file):
        os.remove(config_file)
        print(f"Removed config for {domain_name}")

    # Reload Nginx
    subprocess.run(['sudo', 'nginx', '-s', 'reload'])
    print(f"Removed reverse proxy for {domain_name}")

def list_reverse_proxies():
    proxies = os.listdir(NGINX_CONF_DIR)
    if not proxies:
        print("No reverse proxies configured.")
    else:
        for proxy in proxies:
            print(proxy)

def edit_reverse_proxy(domain_name):
    config_file = os.path.join(NGINX_CONF_DIR, domain_name)
    
    if not os.path.exists(config_file):
        print(f"No configuration found for {domain_name}")
        return
    
    # Open the configuration file in a temporary editor session
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        shutil.copy2(config_file, tmp_file.name)
        editor = os.getenv('EDITOR', 'nano')  # Use the system's default editor, fallback to nano
        subprocess.run([editor, tmp_file.name])
        
        # Replace the original file if the user saved changes
        shutil.copy2(tmp_file.name, config_file)
    
    # Clean up the temporary file
    os.remove(tmp_file.name)
    
    # Reload Nginx
    subprocess.run(['sudo', 'nginx', '-s', 'reload'])
    print(f"Edited and reloaded configuration for {domain_name}")

def main():
    print("Nginx Reverse Proxy Manager")
    print("===========================")
    print("1. Add reverse proxy")
    print("2. Remove reverse proxy")
    print("3. Edit reverse proxy")
    print("4. List reverse proxies")
    print("5. Exit")

    choice = input("Enter your choice: ")

    if choice == '1':
        domain_name = input("Enter domain name: ")
        proxy_pass = input("Enter proxy_pass (e.g., http://localhost:3000): ")
        add_reverse_proxy(domain_name, proxy_pass)
    elif choice == '2':
        domain_name = input("Enter domain name to remove: ")
        remove_reverse_proxy(domain_name)
    elif choice == '3':
        domain_name = input("Enter domain name to edit: ")
        edit_reverse_proxy(domain_name)
    elif choice == '4':
        list_reverse_proxies()
    elif choice == '5':
        exit()
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
