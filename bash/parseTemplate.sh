#!/bin/bash

# Script: parseTemplate.sh
# Description: Generalized script to parse a template file, replace placeholders with user-provided values,
#              and generate a new configuration file with backup functionality.

# Exit immediately if a command exits with a non-zero status
set -e

# Function to prompt for input and ensure it's not empty
prompt_input() {
    local var_name="$1"
    local prompt_message="$2"
    local input

    while true; do
        read -rp "$prompt_message: " input
        if [[ -n "$input" ]]; then
            echo "$input"
            return
        else
            echo "Error: $var_name cannot be empty. Please enter a valid value."
        fi
    done
}

echo "=== Configuration File Generator ==="

# Prompt the user for the template file path
template_file=$(prompt_input "Template File" "Enter the path to the template file")

# Check if the template file exists
if [[ ! -f "$template_file" ]]; then
    echo "Error: Template file '$template_file' not found."
    exit 1
fi

# Prompt the user for the output file name/path
output_file=$(prompt_input "Output File" "Enter the desired output file name/path")

# Backup existing output file if it exists
if [[ -f "$output_file" ]]; then
    backup_file="${output_file}.bak_$(date +%F_%T)"
    cp "$output_file" "$backup_file"
    echo "Backup of existing '$output_file' created as '$backup_file'."
fi

# Initialize an array to hold sed replacement commands
declare -a sed_commands

# Function to add a replacement to the sed_commands array
add_replacement() {
    local placeholder="$1"
    local replacement="$2"
    # Escape forward slashes in placeholder and replacement to prevent sed issues
    placeholder_escaped=$(printf '%s\n' "$placeholder" | sed 's/[\/&]/\\&/g')
    replacement_escaped=$(printf '%s\n' "$replacement" | sed 's/[\/&]/\\&/g')
    sed_commands+=("-e" "s/${placeholder_escaped}/${replacement_escaped}/g")
}

# Loop to collect multiple placeholder-value pairs
while true; do
    echo ""
    echo "Define a placeholder replacement:"
    
    # Prompt for the placeholder (e.g., ${backendIP})
    placeholder=$(prompt_input "Placeholder" "Enter the placeholder to replace (e.g., \${placeholder})")
    
    # Prompt for the replacement value
    replacement=$(prompt_input "Replacement Value" "Enter the value to replace '$placeholder' with")
    
    # Add the replacement to the sed_commands array
    add_replacement "$placeholder" "$replacement"
    
    # Ask if the user wants to add another replacement
    while true; do
        read -rp "Do you want to replace another value? (y/N): " yn
        case "$yn" in
            [Yy]* )
                add_another=true
                break
                ;;
            [Nn]* | "" )
                add_another=false
                break
                ;;
            * )
                echo "Please answer yes (y) or no (n)."
                ;;
        esac
    done

    if [[ "$add_another" = false ]]; then
        break
    fi
done

# Apply the replacements using sed
if [[ ${#sed_commands[@]} -gt 0 ]]; then
    sed "${sed_commands[@]}" "$template_file" > "$output_file"
    echo ""
    echo "Configuration file '$output_file' has been generated successfully with the provided values."
else
    echo "No replacements specified. The output file '$output_file' is identical to the template."
    cp "$template_file" "$output_file"
fi
