#!/bin/bash

# Wrapper script for deploying code using Git

# Define variables
REPO_DIR="/path/to/repo"     # Replace with your repository path
BRANCH="main"
LOGFILE="$REPO_DIR/deploy.log"

# Function to log messages
log() {
  echo "$(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "$LOGFILE"
}

# Function to check for errors
check_error() {
  if [ $? -ne 0 ]; then
    log "Error: $1"
    exit 1
  fi
}

# Change to the repository directory
cd "$REPO_DIR" || { log "Failed to change directory to $REPO_DIR"; exit 1; }

# Pull the latest changes from the remote repository
log "Pulling latest changes from $BRANCH branch..."
git pull origin "$BRANCH"
check_error "Failed to pull latest changes from $BRANCH."

# Merge branches (if needed)
log "Merging development branch into $BRANCH..."
git merge development
check_error "Failed to merge development branch into $BRANCH."

# Push changes to the remote repository
log "Pushing changes to the remote repository..."
git push origin "$BRANCH"
check_error "Failed to push changes to the remote repository."

log "Deployment completed successfully."
