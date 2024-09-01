#!/bin/bash
# ^ this makes it a bash script

# This is a comment, the computer ignores these

# to get the computer to say something
echo "Hello, World!"

# to assign a variable
# Variables: Assign values without spaces around = and reference variables using $.
name="Henry"
echo "Hello, $name!"

# Quoting:
#	Double quotes ("): Preserve variable substitution.
#	Single quotes ('): Preserve literal value.
#	Backticks or $(): Command substitution.
echo "Your current working directory is: $(pwd)"

# Conditionals: if, else, elif.
if [ "$name" == "Henry" ]; then
    echo "Welcome, Henry!"
else
    echo "User not recognized."
fi

# for loop:
for i in {1..5}; do
  echo "Number $i"
done

# while loop:
count=1
while [ $count -le 5 ]; do
  echo "Count: $count"
  ((count++))
done

# Functions
# Define reusable code blocks using functions:
my_function() {
    echo "Hello from a function!"
}

my_function  # Call the function


# Input and Output 
# Reading User Input:
read -p "Enter your name: " name
echo "Hello, $name!"

# Redirecting output
echo "Logging info" > log.txt   # Overwrites the file
echo "More info" >> log.txt    # Appends to the file

# Standard error 
command 2> error.log

# Combine stdout (standard output) and stderr (standard error) (&>):
command &> output.log

#  Exit Status: Every command returns an exit status (0 for success, non-zero for error). Check with $?.
mkdir /some/dir
if [ $? -ne 0 ]; then
    echo "Failed to create directory."
fi

# set Commands:
#	•	set -e: Exit immediately if a command exits with a non-zero status.
#	•	set -u: Treat unset variables as an error.
#	•	set -x: Print each command before executing it (useful for debugging).

# Iterate Over Files:
for file in /path/to/directory/*; do
    echo "Processing $file"
done

# Using Command-Line Arguments
# Access arguments using $1, $2, etc. $@ refers to all arguments, and $# gives the count.
echo "First argument: $1"
echo "All arguments: $@"

# Commonly Used Commands in Scripts
#	•	grep: Search for patterns.
#	•	sed: Stream editor for modifying files.
#	•	awk: Text processing.
#	•	find: Search for files.
#	•	xargs: Build and execute command lines from input.
#	•	cron: Schedule jobs.
