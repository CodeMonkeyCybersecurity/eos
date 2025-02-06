#!/bin/bash
# checkAPI.sh

#!/bin/bash

# Script: generate_nginx_conf.sh
# Description: Prompts the user for WZ_FQDN, WZ_API_PASSWD, and WZ_API_USR,
#              then replaces placeholders in nginx.conf.template with these values.
#              Remembers last-used values in .last_nginx.conf.

set -e

echo ""
echo "============="
echo "  CHECK API  "
echo "============="

# Where we store the last-used values
LAST_VALUES_FILE=".wazuh.conf"

# If we have a saved file from a previous run, load it.
# This defines $WZ_FQDN, $WZ_API_PASSWD, $BASE_DOMAIN if present.
if [[ -f "$LAST_VALUES_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$LAST_VALUES_FILE"
fi

# Function to prompt for input with optional default
prompt_input() {
    local var_name=$1
    local prompt_message=$2
    # Current default (possibly loaded from $LAST_VALUES_FILE) 
    # We use indirect expansion: ${!var_name} refers to the value of the variable whose name is in $var_name
    local default_val=${!var_name}  
    local input

    while true; do
        # Show [default] if we have one
        if [[ -n "$default_val" ]]; then
            read -rp "$prompt_message [$default_val]: " input
        else
            read -rp "$prompt_message: " input
        fi

        if [[ -z "$input" && -n "$default_val" ]]; then
            # If user pressed Enter with no new input, keep the old default
            echo "$default_val"
            return
        elif [[ -n "$input" ]]; then
            # User typed something new, use that
            echo "$input"
            return
        else
            # The user left it empty and there's no default to fall back on
            echo "Error: $var_name cannot be empty. Please enter a valid value."
        fi
    done
}

echo "=== NGINX Configuration Generator ==="

# Prompt for values (will show defaults if any)
WZ_FQDN=$(prompt_input "WZ_FQDN" "Enter the Wazuh domain (eg. wazuh.domain.com):")
WZ_API_USR=$(prompt_input "WZ_API_USR" "Enter the API username (eg. wazuh-wui): ")
WZ_API_PASSWD=$(prompt_input "WZ_API_PASSWD" "Enter the API passwd: ")

TOKEN=$(curl -u "${WZ_API_USR}:${WZ_API_PASSWD}" -k -X POST "https://${WZ_FQDN}:55000/security/user/authenticate?raw=true")

echo ""
echo "Your JWT auth token is:"

echo ""
echo "$TOKEN"

# Save the values so future runs start with the same defaults
cat <<EOF > "$LAST_VALUES_FILE"
WZ_FQDN="$WZ_FQDN"
WZ_API_USR="$WZ_API_USR"
WZ_API_PASSWD="$WZ_API_PASSWD"
TOKEN="$TOKEN"
EOF

chmod 660 *.conf
echo ""
echo "============="
echo "    FINIS    "
echo "============="

set +e
