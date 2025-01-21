 #!/bin/bash

# Check if bash-completion is installed and install if not
if ! command -v complete &> /dev/null; then
    echo "bash-completion is not installed. Installing..."
    sudo apt-get install bash-completion -y
fi

# Add autocomplete settings to .bashrc
BASHRC_FILE="$HOME/.bashrc"

if ! grep -q "source /etc/bash_completion" "$BASHRC_FILE"; then
    echo "Enabling bash-completion in .bashrc..."
    echo -e "\n# Enable bash-completion\nif [ -f /etc/bash_completion ]; then\n    . /etc/bash_completion\nfi" >> "$BASHRC_FILE"
else
    echo "bash-completion is already enabled in .bashrc."
fi

# Reload .bashrc to apply changes
echo "Reloading .bashrc..."
source "$BASHRC_FILE"

echo "Shell text autocomplete is now enabled."
