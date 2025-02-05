#!/bin/bash
# deployWazuh.sh

sudo sysctl -w vm.max_map_count=262144

read -p "what is the most recent wazuh version (eg. 4.10.1) " WZ_VERS

echo "cloning git repo , version ${WZ_VERS}"
git clone https://github.com/wazuh/wazuh-docker.git -b v${WZ_VERS}

echo "entering multi-node directory"
cd wazuh-docker/multi-node

# Ask the user for the proxy address
read -p "Enter the proxy address to use (e.g., proxy.example.com): " HECATE_SUB_DN

# Append the environment block to generate-indexer-certs.yml
cat <<EOF >> generate-indexer-certs.yml

    environment:
      - HTTP_PROXY=${HECATE_SUB_DN}
EOF

# Display the file so the user can verify the changes
echo -e "\nUpdated generate-indexer-certs.yml:"
cat generate-indexer-certs.yml

# Wait for the user to press enter to continue
read -p "Press Enter to continue..."
