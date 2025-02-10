#!/usr/bin/env python3
import os
import sys
import subprocess
import platform
import shutil

def uninstall_macos():
    """
    On macOS, the official Wazuh agent package installs an uninstall script.
    This script is typically located at /Library/Ossec/uninstall.sh.
    """
    uninstall_script = "/Library/Ossec/uninstall.sh"
    if os.path.exists(uninstall_script):
        print("Found uninstall script at", uninstall_script)
        try:
            subprocess.check_call(["sudo", uninstall_script])
            print("Wazuh agent uninstalled successfully on macOS.")
        except subprocess.CalledProcessError as e:
            print("Error during macOS uninstallation:", e)
    else:
        print("Uninstall script not found at", uninstall_script)
        print("Please verify the agent installation location.")

def uninstall_deb():
    """
    On Debian-based systems, remove the Wazuh agent package using apt-get.
    """
    try:
        print("Attempting to uninstall Wazuh agent on a Debian-based system using apt-get purge...")
        subprocess.check_call(["sudo", "apt-get", "purge", "-y", "wazuh-agent"])
        print("Wazuh agent uninstalled successfully on Debian-based system.")
    except subprocess.CalledProcessError as e:
        print("Error during Debian-based uninstallation:", e)

def uninstall_rpm():
    """
    On RPM-based systems, remove the Wazuh agent package using yum or dnf.
    """
    yum_cmd = None
    if shutil.which("yum"):
        yum_cmd = "yum"
    elif shutil.which("dnf"):
        yum_cmd = "dnf"

    if yum_cmd:
        try:
            print(f"Attempting to uninstall Wazuh agent on an RPM-based system using {yum_cmd} remove...")
            subprocess.check_call(["sudo", yum_cmd, "remove", "-y", "wazuh-agent"])
            print("Wazuh agent uninstalled successfully on RPM-based system.")
        except subprocess.CalledProcessError as e:
            print("Error during RPM-based uninstallation:", e)
    else:
        print("Neither yum nor dnf was found. Cannot uninstall Wazuh agent on this RPM-based system.")

def uninstall_windows():
    """
    On Windows, this function uses WMIC to query for the installed Wazuh agent product
    and then invokes msiexec to uninstall it silently.
    
    Make sure to run this script as an Administrator.
    """
    try:
        print("Querying installed products for Wazuh agent...")
        # The WMIC query looks for products with "Wazuh" in their name.
        query_cmd = 'wmic product where "Name like \'%%Wazuh%%\'" get IdentifyingNumber,Name'
        output = subprocess.check_output(query_cmd, shell=True, text=True)
        print("WMIC query output:")
        print(output)
        lines = output.strip().splitlines()

        if len(lines) < 2:
            print("No Wazuh agent found via WMIC.")
            return

        for line in lines[1:]:
            if line.strip():
                # The first column is the IdentifyingNumber (product code)
                # The rest of the line should be the product name.
                parts = line.split()
                product_code = parts[0]
                product_name = " ".join(parts[1:])
                if "Wazuh" in product_name:
                    print("Found product:", product_name, "with code:", product_code)
                    uninstall_cmd = f'msiexec /x {product_code} /qn'
                    print("Uninstalling Wazuh agent using command:", uninstall_cmd)
                    subprocess.check_call(uninstall_cmd, shell=True)
                    print("Wazuh agent uninstalled successfully from Windows.")
                    return
        print("Wazuh agent product not found in WMIC output.")
    except subprocess.CalledProcessError as e:
        print("Error during Windows uninstallation:", e)
    except Exception as e:
        print("General error during Windows uninstallation:", e)

def main():
    current_os = platform.system()
    print("Detected operating system:", current_os)
    if current_os == "Darwin":
        uninstall_macos()
    elif current_os == "Linux":
        # Determine if the Linux distribution is Debian/Ubuntu-based or RPM-based.
        try:
            with open("/etc/os-release") as f:
                os_release = f.read().lower()
                if "debian" in os_release or "ubuntu" in os_release:
                    uninstall_deb()
                elif any(x in os_release for x in ["rhel", "centos", "fedora", "suse"]):
                    uninstall_rpm()
                else:
                    print("Linux distribution not clearly identified; attempting Debian-based removal.")
                    uninstall_deb()
        except Exception as e:
            print("Error reading /etc/os-release:", e)
            print("Attempting Debian-based removal as fallback.")
            uninstall_deb()
    elif current_os == "Windows":
        uninstall_windows()
    else:
        print("Unsupported operating system:", current_os)

if __name__ == "__main__":
    main()
