#!/bin/bash
# deployWazuh.sh

generate_hash () {
    echo "Once you press enter, you will need to re-enter this password in the prompt which appears."
    echo "Make sure the passwords match exactly, if they do not, you won't be able to login"
    echo "After entering your password, a function will scramble your password and output a hash"
    echo "Copy this hash because you will be prompted to enter it before continuing."
    echo "It can be helpful to paste this hash temporarily in your password manager while completing this step"
    echo -p "Press enter to continue..."
    docker compose down
    docker run --rm -ti wazuh/wazuh-indexer:${WZ_VERS} bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
}

apply_user_changes () {
    echo "================================"
    echo "            DEPLOY              "
    echo "================================"
    echo "Once you press enter we will deploy Delphi, powered by Wazuh"
    echo "This will take about 5mins"
    read -p "Press Enter to continue..."
    docker compose up -d

    echo "================================"
    echo "         APPLY CHANGES          "
    echo "================================"
    if [ "$DEPLOY_TYPE" == "1" ]; then
        INDEX_CONTAINER=single-node-wazuh.indexer-1
        APPLY_SCRIPT="bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert  $CACERT -cert $CERT -key $KEY -p 9200 -icl"
    elif [ "$DEPLOY_TYPE" == "2" ]; then
        INDEX_CONTAINER=multi-node-wazuh1.indexer-1
        APPLY_SCRIPT="HOST=$(grep node.name $INSTALLATION_DIR/opensearch.yml | awk '{printf $2}') \ bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert  $CACERT -cert $CERT -key $KEY -p 9200 -icl -h $HOST"
    fi

    echo "After you press enter, we are will enter the container: "${INDEX_CONTAINER}"."
    echo "You need to copy these values:"
    echo ""
    echo "export INSTALLATION_DIR=/usr/share/wazuh-indexer"
    echo "CACERT=$INSTALLATION_DIR/certs/root-ca.pem"
    echo "KEY=$INSTALLATION_DIR/certs/admin-key.pem"
    echo "CERT=$INSTALLATION_DIR/certs/admin.pem"
    echo "export JAVA_HOME=/usr/share/wazuh-indexer/jdk"
    echo ""
    echo "Paste them in the prompt, press enter again, and wait 1-5mins for the changes to apply"
    echo "Once the process is completed, type 'exit' and press enter to return to the main terminal"
    read -p "Press enter when you are ready..." 

    docker exec -it "${INDEX_CONTAINER}" bash

    read -p "We now need to apply the changes we made. Press enter when you are ready..."
    bash -c "${APPLY_SCRIPT}"
}

echo "After you press enter, we will be deleting any old versions"
read -p "Press enter to continue..."
sudo rm -rf wazuh-docker

echo "After you press enter, we will change the vm memory settings for Wazuh to run properly"
read -p "Press enter to continue..."
sudo sysctl -w vm.max_map_count=262144

read -p "Type in the version number of the most recent Wazuh version and press enter (eg. 4.10.1): " WZ_VERS

echo "cloning git repo , version ${WZ_VERS}"
git clone https://github.com/wazuh/wazuh-docker.git -b v${WZ_VERS}

read -p "Do you want to deploy this as a multi-node or single-node install? (type 1 for 'single-node' or 2 for 'multi-node'): " WZ_DEPL_TYPE

if [ "$WZ_DEPL_TYPE" == "1" ]; then
    DEPLOY_TYPE="multi-node"
elif [ "$WZ_DEPL_TYPE" == "2" ]; then
    DEPLOY_TYPE="single-node"
else
    echo "Invalid selection. Please run the script again and choose either 1 or 2."
    exit 1
fi

echo "Deploying as ${DEPLOY_TYPE} install."

# Change directory to the chosen deployment folder
cd "wazuh-docker/${DEPLOY_TYPE}" || { echo "Directory not found. Exiting."; exit 1; }


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

read -p "Press enter to generate the indexer encryption certificates... "
docker compose -f generate-indexer-certs.yml run --rm generator

echo "================================"
echo "     MAKE PORTS COMPATIBLE      "
echo "================================"
echo ""
echo "After you press enter the Wazuh's exposed port will be changed to 8011 to make it compatible with a Eos/Hecate setup"
read -p "Press enter to continue..."
old_BACKEND_PORT="- 443:5601"
new_BACKEND_PORT="- 8011:5601"
sed -i "s|${old_BACKEND_PORT}|${new_BACKEND_PORT}|g" docker-compose.yaml


echo "========================================="
echo "    CHANGE DEFAULT CREDENTIALS:ADMIN     "
echo "========================================="
echo "Before you continue, use a password manager to generate and save three unique and complex passphrases."
echo "Make sure these passphrases DO NOT contain '$' OR '&'"
echo "Mark one of these as for the Admin user, one for your API, and one for your kibana dashboard user"
read -p "Once this is done, press Enter to continue..."

echo "Now we need to change the default password for the Admin user"
read -p "Enter the unique and complex passphrase you made for your Admin user: " WZ_ADMIN_PASSWD
old_WZ_ADMIN_PASSWD="INDEXER_PASSWORD=SecretPassword"
new_WZ_ADMIN_PASSWD="INDEXER_PASSWORD=${WZ_ADMIN_PASSWD}"
sed -i "s|${old_WZ_ADMIN_PASSWD}|${new_WZ_ADMIN_PASSWD}|g" docker-compose.yaml
generate_hash
read -p "Copy the hash value generated above and paste it here: " WZ_ADMIN_BCRYPT
old_WZ_ADMIN_BCRYPT='$2y$12$K/SpwjtB.wOHJ/Nc6GVRDuc1h0rM1DfvziFRNPtk27P.c4yDr9njO'
new_WZ_ADMIN_BCRYPT="${WZ_ADMIN_BCRYPT}"
sed -i "s|${old_WZ_ADMIN_BCRYPT}|${new_WZ_ADMIN_BCRYPT}|g" config/wazuh_indexer/internal_users.yml
apply_user_changes


echo "========================================="
echo " CHANGE DEFAULT CREDENTIALS:KIBANASERVER "
echo "========================================="
read -p "Enter the unique and complex password you made for your kibana dashboard user: " KIB_API_PASSWD
docker run --rm -ti wazuh/wazuh-indexer:${WZ_VERS} bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
old_KIB_API_PASSWD="DASHBOARD_PASSWORD=kibanaserver"
new_KIB_API_PASSWD="DASHBOARD_PASSWORD=${KIB_API_PASSWD}"
sed -i "s|${old_KIB_API_PASSWD}|${new_KIB_API_PASSWD}|g" docker-compose.yaml
generate_hash
read -p "Copy the hash value generated above and paste it here: " WZ_ADMIN_BCRYPT
old_WZ_KIB_BCRYPT='$2a$12$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H.'
new_WZ_KIB_BCRYPT="${WZ_ADMIN_BCRYPT}"
sed -i "s|${old_WZ_KIB_BCRYPT}|${new_WZ_KIB_BCRYPT}|g" config/wazuh_indexer/internal_users.yml
apply_user_changes


echo "================================"
echo " CHANGE DEFAULT CREDENTIALS:API "
echo "================================"
echo "Now we need to change the default password for your API"
read -p "Enter the unique and complex password you made for your API: " WZ_API_PASSWD
docker run --rm -ti wazuh/wazuh-indexer:${WZ_VERS} bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
old_WZ_API_PASSWD="API_PASSWORD=MyS3cr37P450r.*-"
new_WZ_API_PASSWD="API_PASSWORD=${WZ_API_PASSWD}"
sed -i "s|${old_WZ_API_PASSWD}|${new_WZ_API_PASSWD}|g" docker-compose.yaml
sed -i "s|${old_WZ_API_PASSWD}|${new_WZ_API_PASSWD}|g" config/wazuh_dashboard/wazuh.yml
echo "Once you press enter again, we will apply the API changes. This will mean recreating the containers. This will take 1-2mins"
read -p "Press enter to continue..."
docker compose down
docker compose up -d

echo "finis"
