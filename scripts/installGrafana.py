import os
import subprocess

def run_command(command):
    """Run a shell command and handle exceptions."""
    try:
        subprocess.run(command, check=True, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        exit(1)

def prompt_user(prompt, default=None):
    """Prompt the user for input."""
    if default:
        prompt = f"{prompt} [default: {default}]: "
    else:
        prompt = f"{prompt}: "
    response = input(prompt)
    return response.strip() or default

def install_grafana():
    """Install Grafana using container."""
    print("Installing Grafana using container...")

    grafana_version = prompt_user("Enter the Grafana version to install", "latest")
    grafana_port = prompt_user("Enter the port to expose Grafana on", "3000")

    print(f"Pulling Grafana Docker image (version: {grafana_version})...")
    run_command(f"docker pull grafana/grafana:{grafana_version}")

    print("Running Grafana container...")
    run_command(
        f"docker run -d --name=grafana -p {grafana_port}:3000 grafana/grafana:{grafana_version}"
    )

    print(f"Grafana is now running on port {grafana_port}.")

if __name__ == "__main__":
    install_grafana()
