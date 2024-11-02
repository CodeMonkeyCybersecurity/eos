#!/bin/bash

read -p "What is the email you want to use for this git repo?: " EMAIL
git config --global user.email "$EMAIL" && echo "Email set successfully" || echo "Failed to set email"

read -p "What is your name?: " NAME
git config --global user.name "$NAME" && echo "Name set successfully" || echo "Failed to set name"

git config --global pull.rebase false && echo "Pull rebase setting applied" || echo "Failed to set pull rebase"

# Set default branch name to main
git config --global init.defaultBranch main && echo "Default branch name set to 'main'"

# Enable color output
git config --global color.ui auto && echo "Color output enabled for Git"

# Display configuration summary
echo "Git configuration summary:"
git config --list

echo "Finis"
