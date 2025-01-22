#!/bin/bash

# combine_tree_cat.sh
# This script combines the directory structure and file contents of a specified path.

# Function to display usage information
usage() {
    echo "Usage: $0 [directory_path]"
    echo "If no directory_path is provided, the current directory is used."
    exit 1
}

# Check if help is requested
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage
fi

# Set the directory path; default to current directory if not provided
DIR_PATH="${1:-.}"

# Verify that the provided path exists and is a directory
if [ ! -d "$DIR_PATH" ]; then
    echo "Error: '$DIR_PATH' is not a valid directory."
    usage
fi

# Define the output file name based on the provided directory
# Replace slashes with underscores to create a valid file name
SAFE_DIR_NAME=$(echo "$DIR_PATH" | tr '/' '_')
OUTPUT_FILE="$(date)_$(hostname)_dirCodeOverview${SAFE_DIR_NAME}.txt"

# Add a header with the directory path
echo "===== Directory Structure for '$DIR_PATH' =====" > "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Generate directory structure excluding certain folders (e.g., node_modules, .git)
tree -I 'node_modules|.git' "$DIR_PATH" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Add a header for file contents
echo "===== File Contents =====" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Find all files and append their contents with headers
# Adjust the find command to start from the specified directory
find "$DIR_PATH" -type f ! -path "*/node_modules/*" ! -path "*/.git/*" | while read -r file; do
    echo "----- $file -----" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    # Ensure binary files are skipped to avoid corrupting the output
    if file "$file" | grep -qv 'binary'; then
        cat "$file" >> "$OUTPUT_FILE"
    else
        echo "[Binary file skipped]" >> "$OUTPUT_FILE"
    fi
    echo "" >> "$OUTPUT_FILE"
done

echo "Combination complete! Check the '$OUTPUT_FILE' file."