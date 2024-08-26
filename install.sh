#!/bin/bash

# Define the directory where you want to place the 'run' script
INSTALL_DIR="/usr/local/bin/fabric"

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

# Check if the script already exists in the target directory
if [ -f "$SCRIPT_PATH" ]; then
    echo "The script '$SCRIPT_NAME' already exists in $INSTALL_DIR."
    read -p "Do you want to overwrite it? (y/n): " OVERWRITE
    if [ "$OVERWRITE" != "y" ]; then
        echo "Installation aborted."
        exit 1
    fi
fi

# Move the script to the target directory
echo "Moving '$SCRIPT_NAME' to $INSTALL_DIR..."
sudo cp "$SCRIPT_NAME" "$INSTALL_DIR"

# Make the script executable
echo "Making '$SCRIPT_NAME' executable..."
sudo chmod +x "$SCRIPT_PATH"

# Add the directory to PATH if necessary
add_to_path

echo "'$SCRIPT_NAME' has been installed successfully and is available in your PATH."

# Optionally verify by running the command
echo "You can now use the '$SCRIPT_NAME' command from any directory."

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
#     ___         _       __  __          _
#    / __|___  __| |___  |  \/  |___ _ _ | |_____ _  _
#   | (__/ _ \/ _` / -_) | |\/| / _ \ ' \| / / -_) || |
#    \___\___/\__,_\___| |_|  |_\___/_||_|_\_\___|\_, |
#                  / __|  _| |__  ___ _ _         |__/
#                 | (_| || | '_ \/ -_) '_|
#                  \___\_, |_.__/\___|_|
#                      |__/
EOF
