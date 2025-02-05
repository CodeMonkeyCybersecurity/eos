#!/bin/bash
# deployWazuh.sh

echo ""
echo "Hi!"
echo ""
echo "Before installing, we have some house keeping to do"
echo ""
read -p "Press 'Enter' to continue..."

echo ""
echo "After you press 'Enter', we will delete any old versions"
echo ""
read -p "Press 'Enter' to continue..."
sudo rm -rf wazuh-docker
echo ""
echo "We have deleted any old versions from your computer."

echo ""
echo "After you press 'Enter', we will change the vm memory settings for Wazuh to run properly"
echo ""
read -p "Press 'Enter' to continue..."
sudo sysctl -w vm.max_map_count=262144
echo ""
echo "We have changed your vm memory settings."

echo ""
read -p "Type in the version number of the most recent Wazuh version then press 'Enter' (eg. 4.10.1): " WZ_VERS

echo ""
echo "Cloning git repo, version ${WZ_VERS}"
git clone https://github.com/wazuh/wazuh-docker.git -b v${WZ_VERS}

echo ""
read -p "Do you want to deploy this as a multi-node or single-node install? (type 1 for 'single-node' or 2 for 'multi-node'): " WZ_DEPL_TYPE

if [ "$WZ_DEPL_TYPE" == "1" ]; then
    DEPLOY_TYPE="single-node"
    INDEX_CONTAINER="single-node-wazuh.indexer-1"
    APPLY_SCRIPT="'bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert  $CACERT -cert $CERT -key $KEY -p 9200 -icl'"
elif [ "$WZ_DEPL_TYPE" == "2" ]; then
    DEPLOY_TYPE="multi-node"
    INDEX_CONTAINER="multi-node-wazuh1.indexer-1"
    APPLY_SCRIPT='HOST=$(grep node.name $INSTALLATION_DIR/opensearch.yml | awk '"'"'{printf $2}'"'"') \ bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert  $CACERT -cert $CERT -key $KEY -p 9200 -icl -h $HOST'
else
    echo "Invalid selection. Please run the script again and choose either 1 or 2."
    exit 1
fi

echo ""
echo "Deploying as ${DEPLOY_TYPE} install."

# Change directory to the chosen deployment folder
cd "wazuh-docker/${DEPLOY_TYPE}" || { echo "Directory not found. Exiting."; exit 1; }

# Ask the user for the proxy address
echo ""
read -p "'Enter' the proxy address to use (e.g., proxy.example.com): " HECATE_SUB_DN

# Append the environment block to generate-indexer-certs.yml
cat <<EOF >> generate-indexer-certs.yml

    environment:
      - HTTP_PROXY=${HECATE_SUB_DN}
EOF

# Display the file so the user can verify the changes
echo ""
echo -e "\nUpdated generate-indexer-certs.yml:"
cat generate-indexer-certs.yml

echo ""
read -p "Press 'Enter' to generate the indexer encryption certificates... "
echo ""
docker compose -f generate-indexer-certs.yml run --rm generator


echo ""
echo "================================"
echo "     MAKE PORTS COMPATIBLE      "
echo "================================"
echo ""
echo "After you press 'Enter', we will change Wazuh's default exposed port ('443') to '8011'."
echo "This will make it compatible with an Eos/Hecate setup."
echo ""
read -p "Press 'Enter' to continue..."
old_BACKEND_PORT="- 443:5601"
new_BACKEND_PORT="- 8011:5601"
sed -i "s|${old_BACKEND_PORT}|${new_BACKEND_PORT}|g" docker-compose.yml

docker-compose up -d

echo "finis"
