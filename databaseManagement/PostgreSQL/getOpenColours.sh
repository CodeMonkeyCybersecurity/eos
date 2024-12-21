#!/bin/bash
# Define the target database
DATABASE="colours_db"
etch data from the database
COLORS=$(sudo -u postgres psql -d "$DATABASE" -t -c "SELECT colour_name, hex_value, rgb_value FROM open_colours;")
# Loop through each color
echo "$COLORS" | while IFS="|" read -r colour_name hex_value rgb_value; do
    # Trim spaces
    colour_name=$(echo "$colour_name" | xargs)
    hex_value=$(echo "$hex_value" | xargs)
    rgb_value=$(echo "$rgb_value" | xargs)
    
    # Skip if empty
    [ -z "$colour_name" ] && continue

    # Extract RGB values
    IFS="," read -r r g b <<< "$rgb_value"

    # Print the message in the actual color
    echo -e "\e[38;2;${r};${g};${b}mThis is $colour_name. Hex: $hex_value. RGB: $rgb_value\e[0m"
done
echo "All colours displayed. Exiting."