#!/bin/bash

# elevates you to root, then redirects you to your current directory

# Variables
PWD=$(pwd)
echo "Current directory: $PWD"

sudo bash -c "cd '$PWD'; exec bash"  # Use sudo bash -c to run commands as root in the same shell 

echo "you are: $(root)"
echo "Your new current directory is: $PWD"

echo "done"



