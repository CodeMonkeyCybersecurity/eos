#!/usr/bin/env python3
import os
import sys
import subprocess

def find_compose_directories(root_dir):
    """
    Walk the directory tree starting at root_dir and return a set of directories
    that contain a docker-compose file (either docker-compose.yaml or docker-compose.yml).
    """
    compose_dirs = set()
    for current_dir, dirs, files in os.walk(root_dir):
        for file in files:
            if file in ("docker-compose.yaml", "docker-compose.yml"):
                compose_dirs.add(current_dir)
                break  # No need to check other files in this directory.
    return compose_dirs

def run_compose_down(directory):
    """
    Runs 'docker compose down' in the given directory.
    """
    print(f"Running 'docker compose down' in directory: {directory}")
    try:
        subprocess.run(
            ["docker", "compose", "down"],
            cwd=directory,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Error: 'docker compose down' failed in directory {directory}", file=sys.stderr)
        sys.exit(e.returncode)

def main():
    # Use the provided directory as root, or default to the current working directory.
    if len(sys.argv) > 1:
        root_dir = sys.argv[1]
    else:
        root_dir = os.getcwd()

    print(f"Searching for docker-compose files in: {root_dir}")
    compose_dirs = find_compose_directories(root_dir)

    if not compose_dirs:
        print("No docker-compose files found.")
        sys.exit(0)

    # Check if any containers are running (optional).
    try:
        result = subprocess.run(
            ["docker", "ps", "-q"],
            capture_output=True,
            text=True,
            check=True
        )
        running_containers = result.stdout.strip().splitlines()
        if running_containers:
            print("There are running containers. Please stop them before running this script.", file=sys.stderr)
            sys.exit(1)
    except subprocess.CalledProcessError as e:
        print("Error checking running containers.", file=sys.stderr)
        sys.exit(e.returncode)

    # Iterate through each directory and run 'docker compose down'
    for directory in compose_dirs:
        run_compose_down(directory)

    print("All docker compose projects have been brought down.")

if __name__ == '__main__':
    main()
