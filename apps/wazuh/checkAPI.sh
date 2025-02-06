#!/bin/bash
# checkAPI.sh

echo ""
echo "============="
echo "  CHECK API  "
echo "============="

echo ""
read -p "Enter the Wazuh domain (eg. wazuh.domain.com): " WZ_FQDN
echo ""
read -p "Enter the API username (eg. wazuh-wui): " WZ_API_USR
echo ""
read -p "Enter the API passwd: " WZ_API_PASSWD

TOKEN=$(curl -u "${WZ_API_USR}:${WZ_API_PASSWD}" -k -X POST "https://${WZ_FQDN}:55000/security/user/authenticate?raw=true")

echo ""
echo "Your JWT auth token is:"

echo ""
echo "$TOKEN"

echo ""
echo "============="
echo "    FINIS    "
echo "============="
