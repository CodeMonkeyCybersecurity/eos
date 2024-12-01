#!/bin/bash

logError() {
    local errorMessage="$1"
    local logDir="./logs"
    local logFile="$logDir/error.log"

    # Create the logs directory if it doesn't exist
    if [ ! -d "$logDir" ]; then
        mkdir -p "$logDir"
    fi

    # Get the current timestamp
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Format the log entry
    local logEntry
    logEntry="[$timestamp] ERROR: $errorMessage"

    # Append the error message to the log file
    echo "$logEntry" >> "$logFile"

    # Output the error to the console
    echo "An error occurred: $errorMessage" >&2
}

logError
