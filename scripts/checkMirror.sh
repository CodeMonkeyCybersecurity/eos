#!/bin/bash

# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exit 1
fi

# Variables
MIRROR_LIST="http://mirrors.ubuntu.com/mirrors.txt"
DIST=$(lsb_release -sc)
TEST_FILE="dists/$DIST/Release"  # Adjust for your Ubuntu release (e.g., jammy)
TMP_DIR="/tmp/ubuntu-mirror-test"
BEST_MIRROR=""
BEST_TIME=9999

# Create a temporary directory for testing
mkdir -p "$TMP_DIR"

# Fetch mirror list
echo "Fetching mirror list..."
MIRRORS=$(curl -s "$MIRROR_LIST")

if [[ -z "$MIRRORS" ]]; then
    echo "Failed to fetch mirror list. Please check your internet connection."
    exit 1
fi

# Test each mirror
echo "Testing mirrors for speed..."
for MIRROR in $MIRRORS; do
    echo -n "Testing $MIRROR... "
    START_TIME=$(date +%s%3N)
    curl -s --max-time 5 "$MIRROR$TEST_FILE" -o "$TMP_DIR/Release" >/dev/null 2>&1
    END_TIME=$(date +%s%3N)

    if [[ $? -eq 0 ]]; then
        TIME_TAKEN=$((END_TIME - START_TIME))
        echo "Success (${TIME_TAKEN}ms)"
        if [[ $TIME_TAKEN -lt $BEST_TIME ]]; then
            BEST_TIME=$TIME_TAKEN
            BEST_MIRROR=$MIRROR
        fi
    else
        echo "Failed"
    fi
done

# Clean up
rm -rf "$TMP_DIR"

# Output the best mirror
if [[ -n "$BEST_MIRROR" ]]; then
    echo "The fastest mirror is: $BEST_MIRROR"
    echo "Updating /etc/apt/sources.list to use $BEST_MIRROR..."

    # Update sources.list
    sed -i.bak "s|http://.*.ubuntu.com|$BEST_MIRROR|g" /etc/apt/sources.list
    echo "Mirror updated. Backup saved to /etc/apt/sources.list.bak"
    apt update
else
    echo "No suitable mirror found. Please check your network connection."
    exit 1
fi

echo "Mirror testing and update complete."
