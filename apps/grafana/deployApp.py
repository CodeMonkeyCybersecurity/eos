#!/usr/bin/env python3
import os
import glob
import shutil
import subprocess

def main():
    # Get the current working directory
    current_dir = os.getcwd()
    
    # Use the name of the current directory (e.g. "grafana")
    app_dir = os.path.basename(current_dir)
    print(f"Using current directory name (app_dir): {app_dir}")

    # Create the target directory in /opt (e.g. /opt/appname)
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

    # Fix permissions for the target directory so that Grafana can write to volumes or bind mounts.
    # The official Grafana Docker image runs as UID/GID 472, so we adjust ownership accordingly.
    print(f"Fixing ownership of {target_dir} to UID 472:472")
    subprocess.run(["chown", "-R", "472:472", target_dir], check=True)

    # Run 'docker compose up -d' in the new target directory
    print(f"Running 'docker compose up -d' in {target_dir}")
    subprocess.run(["docker", "compose", "up", "-d"], cwd=target_dir, check=True)
    print("Docker compose is now up and running in the new directory.")

if __name__ == '__main__':
    main()
