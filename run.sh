#!/bin/bash
# run.sh

if [ -z "$1" ]; then
    echo "Usage: sudo run <script_path>"
    echo ""
    echo "To see what else you can do with 'run', simply type:"
    echo "sudo run"
    echo ""
    echo "This command allows you to:"
    echo "- Execute any script by providing its path."
    echo "- The script will be made executable and then run."
    exit 1
fi

script_path="$1"

if [ ! -f "$script_path" ]; then
    echo "Error: Script '$script_path' not found."
    exit 1
fi

chmod +x "$script_path"
"$script_path"
