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

# Ensure the source directory exists
if [ ! -d "$SOURCE_DIR" ]; then
  echo "Error: Source directory $SOURCE_DIR does not exist."
  exit 1
fi

# Move all scripts recursively from the source directory to the target directory
echo "Moving scripts from $SOURCE_DIR to $TARGET_DIR"

# Copy all contents of the source directory to the target directory
sudo cp -R "$SOURCE_DIR/"* "$TARGET_DIR/"

# Make all moved scripts executable
echo "Making scripts executable"
sudo chmod -R +x "$TARGET_DIR"/

# Provide feedback
echo "Installation complete."

# ASCII art
cat << "EOF"

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

EOF
