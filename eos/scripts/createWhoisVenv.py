#!/usr/bin/env python3
import os
import sys
import subprocess
import venv

VENV_DIR = "/opt/whois/venv"

def create_venv(venv_dir):
    if not os.path.exists(venv_dir):
        print(f"Creating virtual environment in {venv_dir}...")
        builder = venv.EnvBuilder(with_pip=True)
        builder.create(venv_dir)
        print("Virtual environment created.")
    else:
        print(f"Virtual environment already exists in {venv_dir}")

def install_packages(venv_dir):
    python_executable = os.path.join(venv_dir, "bin", "python3")
    if not os.path.exists(python_executable):
        python_executable = os.path.join(venv_dir, "bin", "python")
    if not os.path.exists(python_executable):
        sys.exit("Python executable not found in the virtual environment.")
    print("Installing required packages (ipwhois, psycopg2-binary)...")
    subprocess.check_call([python_executable, "-m", "pip", "install", "ipwhois", "psycopg2-binary"])
    print("Packages installed.")

def main():
    create_venv(VENV_DIR)
    install_packages(VENV_DIR)
    print(f"You can now run your script using: {VENV_DIR}/bin/python3 /opt/eos/scripts/whois.py")

if __name__ == "__main__":
    main()
