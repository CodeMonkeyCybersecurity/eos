import os
import subprocess
import yaml
from datetime import datetime

# File to track ULAs
ULA_FILE = "ulas.yaml"

def generate_ula():
    # Command to generate the random part of the ULA
    random_part = subprocess.check_output(
        ["openssl", "rand", "-hex", "5"], encoding="utf-8"
    ).strip()
    # Construct the ULA using fd00::/8 and the random part
    ula = f"fd{random_part[0:4]}:{random_part[4:]}::/48"
    return ula

def load_yaml(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return yaml.safe_load(f)
    else:
        return {"ulas": []}

def save_yaml(file_path, data):
    with open(file_path, 'w') as f:
        yaml.safe_dump(data, f, default_flow_style=False)

def update_ula_file(ula):
    data = load_yaml(ULA_FILE)
    new_entry = {
        "ula": ula,
        "generated_at": datetime.now().isoformat()
    }
    data["ulas"].append(new_entry)
    save_yaml(ULA_FILE, data)

def main():
    # Generate ULA
    ula = generate_ula()
    print(f"Generated ULA: {ula}")
    
    # Update YAML file
    update_ula_file(ula)
    print(f"ULA {ula} has been added to {ULA_FILE}")

if __name__ == "__main__":
    main()
