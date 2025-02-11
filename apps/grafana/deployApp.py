#!/usr/bin/env python3

import os
import glob
import shutil
import subprocess

def main():
    # Get the current working directory
    current_dir = os.getcwd()
    
    # Determine the name of the parent directory (last component of the parent path)
    par_dir = os.path.basename(current_dir)
    print(f"Parent directory name (PAR_DIR): {par_dir}")

    # Create the target directory in /opt
    target_dir = os.path.join("/opt", par_dir)
    print(f"Creating target directory: {target_dir}")
    os.makedirs(target_dir, exist_ok=True)

    # Look for docker-compose.yml or docker-compose.yaml in the current directory
    compose_files = glob.glob("docker-compose.yml") + glob.glob("docker-compose.yaml")
    if not compose_files:
        print("No docker-compose.yml or docker-compose.yaml file found in the current directory.")
        return

    # For each compose file found, copy it to the target directory and rename the original file with a .bak extension
    for file in compose_files:
        dest_file = os.path.join(target_dir, os.path.basename(file))
        print(f"Copying {file} to {dest_file}")
        shutil.copy2(file, dest_file)
        
        backup_file = file + ".bak"
        print(f"Renaming {file} to {backup_file}")
        os.rename(file, backup_file)

    # Run 'docker compose up -d' in the new directory
    print(f"Running 'docker compose up -d' in {target_dir}")
    subprocess.run(["docker", "compose", "up", "-d"], cwd=target_dir, check=True)
    print("Docker compose is now up and running in the new directory.")

if __name__ == '__main__':
    main()
