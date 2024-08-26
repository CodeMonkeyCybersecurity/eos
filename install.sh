#!/bin/bash

# Define the target directory
TARGET_DIR="/usr/local/bin/fabric"

# Create the target directory if it doesn't exist
if [ ! -d "$TARGET_DIR" ]; then
  echo "Creating target directory: $TARGET_DIR"
  sudo mkdir -p "$TARGET_DIR"
fi

# Install each script into the target directory
install_script() {
  script_name="$1"
  source_path="$2"

  # Check if the script exists
  if [ ! -f "$source_path/$script_name" ]; then
    echo "Error: Script '$script_name' not found in '$source_path'"
    return 1
  fi

  # Copy the script to the target directory
  echo "Installing '$script_name' to '$TARGET_DIR'"
  sudo cp "$source_path/$script_name" "$TARGET_DIR/"

  # Make the script executable
  sudo chmod +x "$TARGET_DIR/$script_name"
}

# List of scripts to install
scripts=("script1.sh" "script2.sh" "install_borg.sh")

# Directory where the scripts are located
source_dir="$(pwd)"  # Assuming scripts are in the current directory

# Install each script
for script in "${scripts[@]}"; do
  install_script "$script" "$source_dir"
done

# Provide feedback
echo "Installation complete. All scripts are now available in $TARGET_DIR"
