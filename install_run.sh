#!/bin/bash

# Step 1: Confirm that you want to add the command 'run' to the PATH
echo "Do you want to add 'run' to your system's commands (i.e., adding it to PATH) (y/n)?"
read -r YES

if [[ "$YES" == "y" ]]; then
  # Step 2: Check if 'run' is already in /usr/local/bin
  if [ -f "/usr/local/bin/run" ]; then
    echo "Error: The command 'run' already exists in /usr/local/bin."
    echo "Please choose a different name or remove the existing 'run' command."
    exit 1
  fi

  # Step 3: Create the 'run' script in /usr/local/bin
  sudo bash -c 'echo "#!/bin/bash
chmod +x \"\$1\"
./\"\$1\"" > /usr/local/bin/run'
  
  # Step 4: Make the script executable
  sudo chmod +x /usr/local/bin/run
  
  # Step 5: Confirm success
  echo "Command 'run' has been created and added to your PATH."
  echo "You can now use 'run' to execute any of the scripts in this directory."
else
    echo "Skipping 'run' installation."
    exit 0
fi
