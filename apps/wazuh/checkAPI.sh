#!/bin/bash
# checkAPI.sh
# Description: Prompts the user for WZ_FQDN, WZ_API_PASSWD, and WZ_API_USR,
#              then retrieves a JWT auth token from the Wazuh API.
#              Remembers last-used values in .wazuh.conf.

set -e

echo ""
echo "============="
echo "  CHECK API  "
echo "============="

# Where we store the last-used values
LAST_VALUES_FILE=".wazuh.conf"

# If we have a saved file from a previous run, load it.
if [[ -f "$LAST_VALUES_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$LAST_VALUES_FILE"
fi

# Function to prompt for input with optional default
prompt_input() {
    local var_name=$1
    local prompt_message=$2
    local default_val=${!var_name}  
    local input

    while true; do
        if [[ -n "$default_val" ]]; then
            read -rp "$prompt_message [$default_val]: " input
        else
            read -rp "$prompt_message: " input
        fi

        if [[ -z "$input" && -n "$default_val" ]]; then
            echo "$default_val"
            return
        elif [[ -n "$input" ]]; then
            echo "$input"
            return
        else
            echo "Error: $var_name cannot be empty. Please enter a valid value."
        fi
    done
}

echo ""
echo "=== NGINX Configuration Generator ==="

# Prompt for values (will show defaults if any)
WZ_FQDN=$(prompt_input "WZ_FQDN" "Enter the Wazuh domain (eg. wazuh.domain.com):")
WZ_API_USR=$(prompt_input "WZ_API_USR" "Enter the API username (eg. wazuh-wui): ")
WZ_API_PASSWD=$(prompt_input "WZ_API_PASSWD" "Enter the API passwd: ")

# Save the values so future runs start with the same defaults
cat <<EOF > "$LAST_VALUES_FILE"
WZ_FQDN="$WZ_FQDN"
WZ_API_USR="$WZ_API_USR"
WZ_API_PASSWD="$WZ_API_PASSWD"
EOF

echo ""
echo "Retrieving JWT token..."

TOKEN=$(curl -u "${WZ_API_USR}:${WZ_API_PASSWD}" -k -X POST "https://${WZ_FQDN}:55000/security/user/authenticate?raw=true")

echo ""
echo "Your JWT auth token is:"
echo "$TOKEN"
echo ""
echo "============="
echo "    FINIS    "
echo "============="

set +e
