#!/usr/bin/env python3
import os
import sys
import subprocess

def find_compose_directories(root_dir):
    """
    Walk the directory tree starting at root_dir and return a set of directories
    that contain a docker compose file (either docker-compose.yaml or docker-compose.yml).
    """
    compose_dirs = set()
    for current_dir, _, files in os.walk(root_dir):
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

def check_and_stop_running_containers():
    """
    Checks if any containers are running and prompts the user whether to stop them.
    If the user agrees, stops all running containers and rechecks.
    """
    try:
        result = subprocess.run(
            ["docker", "ps", "-q"],
            capture_output=True,
            text=True,
            check=True
        )
        running_containers = result.stdout.strip().splitlines()
        if running_containers:
            print("There are running containers. Would you like us to stop these? [y/N]")
            answer = input().strip().lower()
            if answer in ('y', 'yes'):
                print("Stopping running containers...")
                for container in running_containers:
                    subprocess.run(["docker", "stop", container], check=True)
                # Re-check if any containers are still running.
                result = subprocess.run(
                    ["docker", "ps", "-q"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                running_containers = result.stdout.strip().splitlines()
                if running_containers:
                    print("Some containers are still running. Please stop them manually.", file=sys.stderr)
                    sys.exit(1)
                else:
                    print("All running containers have been stopped.")
            else:
                print("Please stop the running containers before running this script.", file=sys.stderr)
                sys.exit(1)
    except subprocess.CalledProcessError as e:
        print("Error checking running containers.", file=sys.stderr)
        sys.exit(e.returncode)


def main():
    # Define common directories to search. Adjust these as needed.
    common_dirs = []

    # Always include the user's home directory if available.
    home = os.environ.get("HOME")
    if home:
        common_dirs.append(home)

    # Optionally add other directories that might contain projects.
    for d in ["/opt", "/srv", "/home"]:
        if os.path.isdir(d):
            common_dirs.append(d)

    if not common_dirs:
        print("No common directories to search. Exiting.", file=sys.stderr)
        sys.exit(1)

    print("Searching for docker compose files in common directories:")
    for d in common_dirs:
        print("  " + d)


    # Collect all directories that contain a docker compose file.
    all_compose_dirs = set()
    for root in common_dirs:
        found_dirs = find_compose_directories(root)
        if found_dirs:
            print(f"Found {len(found_dirs)} docker compose project(s) in '{root}'.")
            all_compose_dirs.update(found_dirs)

    if not all_compose_dirs:
        print("No docker compose files were found in the common directories.")
        sys.exit(0)


    # Check for running containers and ask if the script should stop them.
    check_and_stop_running_containers()

    # Iterate through each directory and run 'docker compose down'
    for directory in all_compose_dirs:
        run_compose_down(directory)

    print("All docker compose projects have been brought down.")

if __name__ == '__main__':
    main()
