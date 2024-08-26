#!/bin/bash

# Define the target directory
TARGET_DIR="/usr/local/bin/fabric"

# Create the target directory if it doesn't exist
if [ ! -d "$TARGET_DIR" ]; then
  echo "Creating target directory: $TARGET_DIR"
  sudo mkdir -p "$TARGET_DIR"
fi

# Directory where the scripts are located
SOURCE_DIR="$(pwd)/scripts"  # Change this if your scripts are in a different directory

# Move all scripts recursively from the source directory to the target directory
echo "Moving scripts from $SOURCE_DIR to $TARGET_DIR"

# Find all files in the source directory and move them to the target directory
find "$SOURCE_DIR" -type f -name "*.sh" -exec sudo mv {} "$TARGET_DIR/" \;

# Make all moved scripts executable
echo "Making scripts executable"
sudo chmod +x "$TARGET_DIR"/*.sh

# Provide feedback
echo "Installation complete."
