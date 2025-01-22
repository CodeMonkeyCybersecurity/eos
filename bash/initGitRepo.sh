#!/bin/bash

# Function to display a header
function print_header() {
    echo "=============================="
    echo "$1"
    echo "=============================="
}

# Step 1: Check if Git is installed
if ! command -v git &>/dev/null; then
    echo "Error: Git is not installed. Please install Git and try again."
    exit 1
fi

# Step 2: Prompt for the Git repository root directory
print_header "Specify the Git Repository Root Directory"
read -p "Enter the absolute path for the new Git repository (default: current directory): " repo_dir
repo_dir=${repo_dir:-$(pwd)}

# Check if the directory exists
if [ ! -d "$repo_dir" ]; then
    echo "Error: Directory '$repo_dir' does not exist. Please create it first."
    exit 1
fi

# Navigate to the specified directory
cd "$repo_dir" || exit
echo "Working directory set to: $repo_dir"

# Step 3: Initialize the Git repository
print_header "Initializing Git Repository"
if [ ! -d ".git" ]; then
    git init
    echo "Git repository initialized in '$repo_dir'."
else
    echo "Git repository already exists in '$repo_dir'."
fi

# Step 4: Add all files to the repository
print_header "Adding Files to Repository"
git add .
echo "All files added to the staging area."

# Step 5: Commit the changes
print_header "Committing Files"
read -p "Enter a commit message [Default: 'Initial commit']: " commit_message
commit_message=${commit_message:-"Initial commit"}
git commit -m "$commit_message"
echo "Files committed with message: '$commit_message'"

# Step 6: Check if GitHub CLI is installed
if ! command -v gh &>/dev/null; then
    echo "Error: GitHub CLI (gh) is not installed. Please install it and try again."
    exit 1
fi

# Step 7: Authenticate with GitHub if not already logged in
if ! gh auth status &>/dev/null; then
    echo "You are not logged into GitHub. Starting authentication..."
    gh auth login
fi

# Step 8: Set up the remote repository
print_header "Setting Up Remote Repository"
read -p "Enter your Git remote repository URL (e.g., https://github.com/username/repo.git): " remote_url
git remote add origin "$remote_url"
git branch -M main
git push -u origin main
echo "Remote repository set up and changes pushed."

# Step 9: Verify Repository Status and History
print_header "Repository Status and History"
git status
git log --oneline

# Final message
echo "Your Git repository setup in '$repo_dir' is complete!"
echo "Finis"
