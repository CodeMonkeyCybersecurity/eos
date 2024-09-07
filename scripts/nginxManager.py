import os
import subprocess

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

def main():
    print("Nginx Reverse Proxy Manager")
    print("===========================")
    print("1. Add reverse proxy")
    print("2. Remove reverse proxy")
    print("3. List reverse proxies")
    print("4. Exit")

    choice = input("Enter your choice: ")

    if choice == '1':
        domain_name = input("Enter domain name: ")
        proxy_pass = input("Enter proxy_pass (e.g., http://localhost:3000): ")
        add_reverse_proxy(domain_name, proxy_pass)
    elif choice == '2':
        domain_name = input("Enter domain name to remove: ")
        remove_reverse_proxy(domain_name)
    elif choice == '3':
        list_reverse_proxies()
    elif choice == '4':
        exit()
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
