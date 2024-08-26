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




       #                 ____---------_____
       #               / ___/-----------___ \
       #            _| _/      _______     \ \
       #          _| /   __   |_______ \     \ \
       #         | |   / /             \ \    \ |_
       #        | |   | |   __________   \ \   \ |_
       #       | |   | |   /  _______  \   | |  |_ |
       #       | |  | |   | |   __    | |  | |   | |
       #       | |  | |   |_|   | |   | |  | |   | |
       #       | |  \_|    __   | |   | |  |_|   | |
       #        \ \       | |   / /   / /  __   |_/
       #         \_\      \_|  | |   | |   | |
       #                       \_/   \_/   |_/                    
       #   ___         _       __  __          _
       #  / __|___  __| |___  |  \/  |___ _ _ | |_____ _  _
       # | (__/ _ \/ _` / -_) | |\/| / _ \ ' \| / / -_) || |
       #  \___\___/\__,_\___| |_|  |_\___/_||_|_\_\___|\_, |
       #                / __|  _| |__  ___ _ _         |__/
       #               | (_| || | '_ \/ -_) '_|
       #                \___\_, |_.__/\___|_|
       #                    |__/

