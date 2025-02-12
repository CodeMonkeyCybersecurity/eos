#!/usr/bin/env python3
import os
import glob
import shutil
import subprocess

def update_compose_file(compose_path):
    """Replace volume mapping './grafana-data' with './' to mount the entire directory."""
    try:
        with open(compose_path, 'r') as f:
            content = f.read()
        # If the file contains a mapping using './grafana-data', replace it with './'
        if './grafana-data' in content:
            new_content = content.replace('./grafana-data', '.')
            with open(compose_path, 'w') as f:
                f.write(new_content)
            print(f"Updated volume mapping in {compose_path} to use './' instead of './grafana-data'.")
        else:
            print(f"No volume mapping './grafana-data' found in {compose_path}. No change made.")
    except Exception as e:
        print(f"Error updating {compose_path}: {e}")

def main():
    # Get the current working directory
    current_dir = os.getcwd()
    
    # Use the name of the current directory (e.g. "grafana")
    app_dir = os.path.basename(current_dir)
    print(f"Using current directory name (app_dir): {app_dir}")

    # Create the target directory in /opt (e.g. /opt/grafana)
    target_dir = os.path.join("/opt", app_dir)
    print(f"Creating target directory: {target_dir}")
    os.makedirs(target_dir, exist_ok=True)

    # Look for docker-compose.yml or docker-compose.yaml in the current directory
    compose_files = glob.glob("docker-compose.yml") + glob.glob("docker-compose.yaml")
    if not compose_files:
        print("No docker-compose.yml or docker-compose.yaml file found in the current directory.")
        return

    # For each compose file found, copy it to the target directory and rename the original with a .bak extension
    for file in compose_files:
        dest_file = os.path.join(target_dir, os.path.basename(file))
        print(f"Copying {file} to {dest_file}")
        shutil.copy2(file, dest_file)
        
        # Update the docker-compose file to change the volume mapping if needed.
        update_compose_file(dest_file)

    # Fix permissions for the target directory so that Grafana can write to /var/lib/grafana.
    # The official Grafana Docker image runs as UID/GID 472, so we adjust ownership accordingly.
    print(f"Fixing ownership of {target_dir} to UID 472:472")
    subprocess.run(["chown", "-R", "472:472", target_dir], check=True)

    # Run 'docker compose up -d' in the new target directory
    print(f"Running 'docker compose up -d' in {target_dir}")
    subprocess.run(["docker", "compose", "up", "-d"], cwd=target_dir, check=True)
    print("Docker compose is now up and running in the new directory.")

if __name__ == '__main__':
    main()
