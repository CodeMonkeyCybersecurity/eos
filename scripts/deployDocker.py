#!/usr/bin/env python3
import os
import sys
import subprocess

def run_command(cmd, shell=False, check=True, capture_output=False, input_text=None):
    """Run a command and print it before executing."""
    print("Running:", " ".join(cmd) if isinstance(cmd, list) else cmd)
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            check=check,
            capture_output=capture_output,
            text=True,
            input=input_text
        )
        return result
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}", file=sys.stderr)
        sys.exit(e.returncode)

def require_root():
    if os.geteuid() != 0:
        print("This script must be run as root (try sudo).", file=sys.stderr)
        sys.exit(1)

def uninstall_conflicting_packages():
    packages = [
        "docker.io", "docker-doc", "docker-compose", "docker-compose-v2",
        "podman-docker", "containerd", "runc"
    ]
    print("\nUninstalling conflicting packages...")
    for pkg in packages:
        run_command([ "apt-get", "remove", "-y", pkg], check=False)  # ignore errors if package is not installed

def uninstall_snap_docker():
    print("\nUninstalling Docker if installed via snap...")
    run_command(["snap", "remove", "docker"], check=False)

def update_apt_repos():
    print("\nUpdating apt repositories and cleaning up...")
    run_command(["apt", "update"])
    run_command(["apt", "autoremove", "--purge", "-y"])
    run_command(["apt", "autoclean"])

def install_prerequisites_and_gpg():
    print("\nInstalling prerequisites and adding Docker's official GPG key...")
    run_command([ "apt-get", "update"])
    run_command([ "apt-get", "install", "-y", "ca-certificates", "curl"])
    run_command(["install", "-m", "0755", "-d", "/etc/apt/keyrings"])
    run_command(["curl", "-fsSL", "https://download.docker.com/linux/ubuntu/gpg",
                 "-o", "/etc/apt/keyrings/docker.asc"])
    run_command(["chmod", "a+r", "/etc/apt/keyrings/docker.asc"])

def get_ubuntu_codename():
    """Parse /etc/os-release to get UBUNTU_CODENAME or VERSION_CODENAME."""
    codename = None
    try:
        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.startswith("UBUNTU_CODENAME="):
                    codename = line.strip().split("=")[1].strip('"')
                    break
                if line.startswith("VERSION_CODENAME=") and not codename:
                    codename = line.strip().split("=")[1].strip('"')
    except Exception as e:
        print("Error reading /etc/os-release:", e, file=sys.stderr)
    if not codename:
        print("Could not determine Ubuntu codename.", file=sys.stderr)
        sys.exit(1)
    return codename

def get_architecture():
    """Return the architecture string from dpkg --print-architecture."""
    result = run_command(["dpkg", "--print-architecture"], capture_output=True)
    return result.stdout.strip()

def add_docker_repo():
    print("\nAdding Docker repository to Apt sources...")
    arch = get_architecture()
    codename = get_ubuntu_codename()
    # Build the repository line.
    repo_line = (
        f"deb [arch={arch} signed-by=/etc/apt/keyrings/docker.asc] "
        f"https://download.docker.com/linux/ubuntu {codename} stable\n"
    )
    repo_file = "/etc/apt/sources.list.d/docker.list"
    try:
        with open(repo_file, "w") as f:
            f.write(repo_line)
        print(f"Repository added to {repo_file}")
    except Exception as e:
        print("Error writing repository file:", e, file=sys.stderr)
        sys.exit(1)
    run_command([ "apt-get", "update"])

def install_docker():
    print("\nInstalling the latest Docker packages...")
    packages = [
        "docker-ce", "docker-ce-cli", "containerd.io",
        "docker-buildx-plugin", "docker-compose-plugin"
    ]
    run_command([ "apt-get", "install", "-y"] + packages)

def verify_docker_hello_world(use_sudo=True):
    print("\nVerifying Docker installation by running hello-world...")
    cmd = ["docker", "run", "hello-world"]
    if use_sudo:
        cmd.insert(0, "sudo")
    run_command(cmd)

def setup_docker_non_root():
    print("\nRunning Linux post-installation steps to allow Docker as a non-root user...")
    # Try to add the docker group (ignore if it already exists)
    run_command(["groupadd", "docker"], check=False)
    # Determine the non-root user.
    user = os.environ.get("SUDO_USER") or os.environ.get("USER")
    if not user or user == "root":
        print("No non-root user detected; skipping usermod step.", file=sys.stderr)
    else:
        run_command(["usermod", "-aG", "docker", user])
        print(f"User '{user}' has been added to the docker group.")
    print("Note: To apply the new group membership, please log out and log back in (or run 'newgrp docker').")

def main():
    require_root()

    uninstall_conflicting_packages()
    uninstall_snap_docker()
    update_apt_repos()
    install_prerequisites_and_gpg()
    add_docker_repo()
    install_docker()
    verify_docker_hello_world(use_sudo=True)
    setup_docker_non_root()
    # Try to verify Docker without sudo.
    verify_docker_hello_world(use_sudo=False)
    
    print("\nDocker installation and post-installation steps complete.")

if __name__ == "__main__":
    main()
