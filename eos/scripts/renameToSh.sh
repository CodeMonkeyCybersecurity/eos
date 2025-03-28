#!/bin/bash


#This script iterates over all files in the current directory and checks if the file name does not contain a dot (meaning it has no extension). 
#If so, it renames the file by appending .sh to its name. 
#Files with extensions like .py and .mjs will remain unchanged.
for file in *; do
  if [[ ! $file == *.* ]]; then
    mv "$file" "$file.sh"
  fi
done
