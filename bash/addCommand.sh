#!/bin/bash
# add_command.sh

# Step 1: Ask for the command name
read -p "Enter the name you want to use to call the command: " command_name

# Step 2: Ask for the command you want to add
read -p "Enter the command or script you want to execute: " command_content

# Step 3: Define the directory to store the command
target_dir="/usr/local/bin"

# Step 4: Create the script file
script_path="$target_dir/$command_name"

# Check if the script already exists
if [ -f "$script_path" ]; then
    echo "A command with this name already exists in $target_dir. Please choose a different name."
    exit 1
fi

# Write the command content to the script file
echo -e "#!/bin/bash\n$command_content" | sudo tee "$script_path" > /dev/null

# Step 5: Make the script executable
sudo chmod +x "$script_path"

# Step 6: Confirm success
echo "Command '$command_name' has been created and added to $target_dir."
echo "You can now use '$command_name' to execute: $command_content"
