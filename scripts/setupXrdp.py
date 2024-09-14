import os
import subprocess

def run_command(command, input_needed=False):
    """Run a shell command and handle user inputs if needed."""
    try:
        if input_needed:
            print(f"Running interactive command: '{command}'. Please follow the instructions in the terminal.")
            os.system(command)  # Using os.system for interactive terminal commands
        else:
            result = subprocess.run(command, shell=True, check=True)
            return result
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while running the command: {e}")
        exit(1)
    except TypeError as e:
        print(f"TypeError occurred: {e}")
        exit(1)

def install_desktop_environment():
    """Install Xfce desktop environment and required packages."""
    print("Updating package lists...")
    run_command('sudo apt update')
    
    print("Installing Xfce desktop environment...")
    run_command('sudo apt install xfce4 xfce4-goodies -y')
    
    print("Selecting display manager (gdm3 recommended)...")
    # Use os.system for interactive terminal commands
    run_command('sudo dpkg-reconfigure lightdm', input_needed=True)

def install_xrdp():
    """Install xrdp on Ubuntu and start the service."""
    print("Installing xrdp...")
    run_command('sudo apt install xrdp -y')
    
    print("Starting xrdp service...")
    run_command('sudo systemctl start xrdp')

    print("Enabling xrdp service to start on boot...")
    run_command('sudo systemctl enable xrdp')
    
    print("Checking xrdp status...")
    run_command('sudo systemctl status xrdp')

def configure_xrdp():
    """Configure xrdp and allow the RDP port in the firewall."""
    print("Configuring xrdp...")
    run_command('sudo nano /etc/xrdp/xrdp.ini', input_needed=True)

    print("Setting up the .xsession file for xfce4-session...")
    run_command('echo "xfce4-session" | tee ~/.xsession')

    print("Restarting xrdp service...")
    run_command('sudo systemctl restart xrdp')

def configure_firewall():
    """Configure the firewall to allow RDP connections on port 3389."""
    print("Retrieving your public IP...")
    result = subprocess.run("curl -s ifconfig.me", shell=True, capture_output=True, text=True)
    public_ip = result.stdout.strip()

    print(f"Your public IP is: {public_ip}")
    print("Allowing RDP connections from your IP on port 3389...")
    run_command(f'sudo ufw allow from {public_ip}/32 to any port 3389')

    print("Verifying firewall status...")
    run_command('sudo ufw status')

def test_rdp_connection():
    """Instructions for testing RDP connection from different operating systems."""
    print("\nTesting RDP Connection:")
    print("1. On Windows: Use the Remote Desktop Connection application.")
    print("2. On macOS: Use the Microsoft Remote Desktop app.")
    print("3. On Linux: Install and use Remmina or another RDP client.")

def main():
    print("Welcome to the RDP Setup Wizard for Ubuntu 22.04")
    
    # Step 1: Install Desktop Environment
    install_desktop_environment()
    
    # Step 2: Install xrdp
    install_xrdp()
    
    # Step 3: Configure xrdp and Firewall
    configure_xrdp()
    configure_firewall()

    # Step 4: Test RDP Connection
    test_rdp_connection()

    print("\nSetup complete! You can now connect to your Ubuntu server using RDP.")

if __name__ == "__main__":
    main()
