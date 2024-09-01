#!/bin/bash

# Define the directory where you want to place the 'run' script
INSTALL_DIR="/usr/local/bin/fabric"
FABRIC_CONFIGS="/etc/fabric"
FABRIC_LOGS="/var/log/fabric"

# Define the name of the script
SCRIPT_NAME="run"

# Full path to the script
SCRIPT_PATH="$INSTALL_DIR/$SCRIPT_NAME"

# Function to add the directory to PATH in .bashrc or .zshrc
add_to_path() {
    SHELL_RC=""
    if [ -f "$HOME/.bashrc" ]; then
        SHELL_RC="$HOME/.bashrc"
    elif [ -f "$HOME/.zshrc" ]; then
        SHELL_RC="$HOME/.zshrc"
    else
        echo "Neither .bashrc nor .zshrc found. Please add $INSTALL_DIR to your PATH manually."
        exit 1
    fi

    if ! grep -q "$INSTALL_DIR" "$SHELL_RC"; then
        echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> "$SHELL_RC"
        echo "$INSTALL_DIR has been added to your PATH in $SHELL_RC"
        source "$SHELL_RC"
    else
        echo "$INSTALL_DIR is already in your PATH."
    fi
}

# Perform a clean installation by removing the old directory if it exists
if [ -d "$INSTALL_DIR" ]; then
    echo "Removing existing installation at $INSTALL_DIR..."
    sudo rm -rf "$INSTALL_DIR"
fi

# Recreate the directory for a fresh installation
echo "Creating target directories: $INSTALL_DIR $FABRIC_CONFIGS $FABRIC_LOGS"
sudo mkdir -p "$INSTALL_DIR" "$FABRIC_CONFIGS" "$FABRIC_LOGS"

# Move the script to the target directory
echo "Moving '$SCRIPT_NAME' to $INSTALL_DIR..."
if [ -f "$SCRIPT_NAME" ]; then
    sudo cp "$SCRIPT_NAME" "$INSTALL_DIR"
else
    echo "Error: Script '$SCRIPT_NAME' not found in the current directory."
    exit 1
fi

# Make the script executable
echo "Making '$SCRIPT_NAME' executable..."
sudo chmod +x "$SCRIPT_PATH"

# Add the directory to PATH if necessary
add_to_path

echo "'$SCRIPT_NAME' has been installed successfully and is available in your PATH."

# Directory where the scripts are located
SOURCE_DIR="$(pwd)/scripts/*"  # Change this if your scripts are in a different directory

# Ensure the source directory exists
if [ ! -d "$SOURCE_DIR" ]; then
  echo "Error: Source directory $SOURCE_DIR does not exist."
  exit 1
fi

# Move all scripts recursively from the source directory to the target directory
echo "Moving scripts from $SOURCE_DIR to $INSTALL_DIR"

# Copy all contents of the source directory to the target directory
sudo cp -R "$SOURCE_DIR/"* "$INSTALL_DIR/"

# Make all moved scripts executable
echo "Making scripts executable"
sudo chmod -R +x "$INSTALL_DIR/"

echo "Installation complete."
echo "Current PATH: $PATH"

# ASCII art
cat << "EOF"
#     ___         _       __  __          _
#    / __|___  __| |___  |  \/  |___ _ _ | |_____ _  _
#   | (__/ _ \/ _` / -_) | |\/| / _ \ ' \| / / -_) || |
#    \___\___/\__,_\___| |_|  |_\___/_||_|_\_\___|\_, |
#                  / __|  _| |__  ___ _ _         |__/
#                 | (_| || | '_ \/ -_) '_|
#                  \___\_, |_.__/\___|_|
#                      |__/
EOF
