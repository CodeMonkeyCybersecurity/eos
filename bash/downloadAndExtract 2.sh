#!/bin/bash

# Prompt the user for the download URL
read -p "Enter the URL of the tar.gz file to download: " url

# Prompt the user for the output filename
read -p "Enter the output filename (default: example.tar.gz): " filename
filename=${filename:-example.tar.gz}

# Download the tar.gz file
curl -o "$filename" "$url"

# Prompt the user for the extraction directory
read -p "Enter the directory to extract to (default: current directory): " extract_dir
extract_dir=${extract_dir:-.}

# Extract the file
tar -xvzf "$filename" -C "$extract_dir"

echo "File downloaded and extracted to $extract_dir."
