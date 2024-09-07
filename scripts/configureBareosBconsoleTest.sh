#!/bin/bash

# Function to display a message and exit with an error code
function error_exit {
    echo "Error: $1" 1>&2
    exit 1
}

# Check if bconsole is available
if ! command -v bconsole &> /dev/null; then
    error_exit "bconsole command not found. Make sure Bareos is installed and configured correctly."
fi

# Run bconsole commands
bconsole <<END_OF_DATA
@output /dev/null
messages
@output /tmp/log1.out
label volume=TestVolume001
run job=Client1 yes
wait
messages
@#
@# now do a restore
@#
@output /tmp/log2.out
restore current all
yes
wait
messages
@output
quit
END_OF_DATA

# Check if the bconsole execution was successful
if [[ $? -ne 0 ]]; then
    error_exit "bconsole command failed."
else
    echo "bconsole commands executed successfully."
fi

# Optional: Display logs for review
echo "Displaying /tmp/log1.out:"
cat /tmp/log1.out

echo "Displaying /tmp/log2.out:"
cat /tmp/log2.out

grep "^ *Termination: *Backup OK" /tmp/log1.out
backupstat=$?
grep "^ *Termination: *Restore OK" /tmp/log2.out
restorestat=$?
