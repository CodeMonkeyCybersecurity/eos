#!/bin/bash

# Define the target database
DATABASE="colours_db"

# Fetch data from the database
COLORS=$(sudo -u postgres psql -d "$DATABASE" -t -c "SELECT colour_name, hex_value FROM solarized;")

# Loop through each color
echo "$COLORS" | while IFS="|" read -r colour_name hex_value; do
    # Trim spaces
    colour_name=$(echo "$colour_name" | xargs)
    hex_value=$(echo "$hex_value" | xargs)
    
    # Skip if empty
    [ -z "$colour_name" ] && continue
    
    # Convert HEX to RGB (terminal requires RGB for colors)
    r=$(printf "%d" 0x${hex_value:1:2})
    g=$(printf "%d" 0x${hex_value:3:2})
    b=$(printf "%d" 0x${hex_value:5:2})
    
    # Print the message in the actual color
    echo -e "\e[38;2;${r};${g};${b}mThis is $colour_name and its hex is $hex_value\e[0m"
done

echo "All colours displayed. Exiting."