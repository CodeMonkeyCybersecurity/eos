#!/bin/bash

OUTPUT_FILE="($date)_$(hostname)_directoryCodeOverview.txt"

# Add a header
echo "===== Directory Structure =====" > $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

# Generate directory structure excluding certain folders (e.g., node_modules, .git)
tree -I 'node_modules|.git' >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

# Add a header for file contents
echo "===== File Contents =====" >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

# Find all files and append their contents with headers
find . -type f ! -path "./node_modules/*" ! -path "./.git/*" | while read file; do
    echo "----- $file -----" >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
    cat "$file" >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
done

echo "Combination complete! Check the $OUTPUT_FILE file."