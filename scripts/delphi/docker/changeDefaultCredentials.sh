#!/bin/bash
# changeDefaultCredentials.sh

generate_hash () {
    echo ""
    echo "================================"
    echo "         GENERATE HASH          "
    echo "================================"
    echo ""
    echo ""
    echo "Once you press 'Enter', you will need to re-enter this password in the prompt that appears."
    echo "Make sure the passwords match exactly, if they do not, you won't be able to login."
    echo "After entering your password, a function will scramble your password and output a hash."
    echo ""
    echo "Copy this hash because you will be prompted to re-enter it before continuing."
    echo "It can be helpful to paste this hash temporarily in your password manager while completing this step."
    echo ""
    read -p "Press 'Enter' to continue..."
    echo ""
    docker run --rm -ti wazuh/wazuh-indexer:${WZ_VERS} bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
    echo ""
}

apply_user_changes () {
    echo ""
    echo "================================"
    echo "            DEPLOY              "
    echo "================================"
    echo ""
    echo "Once you hit 'Enter' we will deploy Delphi, powered by Wazuh."
    echo "This will take about 5mins."
    echo ""
    read -p "Press 'Enter' to continue..."
    docker compose up -d
    echo ""
    echo "================================"
    echo "         APPLY CHANGES          "
    echo "================================"
    echo ""
    echo "After you press 'Enter', we are will move into the container: "${INDEX_CONTAINER}"."
    echo "You need to copy this code:"
    echo ""
    echo "export INSTALLATION_DIR=/usr/share/wazuh-indexer"
    echo "CACERT=$INSTALLATION_DIR/certs/root-ca.pem"
    echo "KEY=$INSTALLATION_DIR/certs/admin-key.pem"
    echo "CERT=$INSTALLATION_DIR/certs/admin.pem"
    echo "export JAVA_HOME=/usr/share/wazuh-indexer/jdk"
    echo ""
    echo "Paste it into the bash shell, press 'Enter', then WAIT TWO TO FIVE MINS"
    echo ""
    echo "After this wait, copy this code:"
    echo ""
    echo "${APPLY_SCRIPT}"
    echo ""
    echo "Paste it into the prompt, press 'Enter' again, and wait for the short process to complete"
    echo ""
    echo "After the process completes, type 'exit' to return to the main shell here."
    read -p "Press 'Enter' when you are ready..."
    echo ""
    docker exec -it "${INDEX_CONTAINER}" bash
}

echo ""
echo "Hi!"
echo ""
echo "Before installing, we have some house keeping to do"
echo ""
read -p "Press 'Enter' to continue..."
echo ""
read -p "Type in the version number of the most recent Wazuh version then press 'Enter' (eg. 4.10.1): " WZ_VERS
echo ""
read -p "Is this a multi-node or single-node install? (type 1 for 'single-node' or 2 for 'multi-node'): " WZ_DEPL_TYPE

if [ "$WZ_DEPL_TYPE" == "1" ]; then
    DEPLOY_TYPE="single-node"
    INDEX_CONTAINER="single-node-wazuh.indexer-1"
    APPLY_SCRIPT="'bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert  $CACERT -cert $CERT -key $KEY -p 9200 -icl'"
elif [ "$WZ_DEPL_TYPE" == "2" ]; then
    DEPLOY_TYPE="multi-node"
    INDEX_CONTAINER="multi-node-wazuh1.indexer-1"
    APPLY_SCRIPT='HOST=$(grep node.name $INSTALLATION_DIR/opensearch.yml | awk '"'"'{printf $2}'"'"') \ 
    bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert  $CACERT -cert $CERT -key $KEY -p 9200 -icl -h $HOST'
else
    echo "Invalid selection. Please run the script again and choose either 1 or 2."
    exit 1
fi

echo ""
echo "After you press 'Enter', we will temporarily bring Wazuh down. All your data will be preserved."
echo ""
read -p "Press 'Enter' to continue..."
cd wazuh-docker/${DEPLOY_TYPE}
docker compose down
echo ""
echo "Wazuh is off so now we can change the user credentials."
echo ""
echo "========================================="
echo "    CHANGE DEFAULT CREDENTIALS:ADMIN     "
echo "========================================="
echo ""
echo "Before you continue, use a password manager to generate and save three unique and complex passphrases."
echo "Make sure these passphrases DO NOT contain '$' OR '&'."
echo ""
echo "Mark one of these as for the Admin user, one for your API, and one for your kibana dashboard user."
echo ""
read -p "Once this is done, press 'Enter' to continue..."
echo ""
echo "Now we need to change the default password for the Admin user."
echo ""
read -p "Type in the unique and complex passphrase you made for your Admin user, then press 'Enter' to continue: " WZ_ADMIN_PASSWD
old_WZ_ADMIN_PASSWD="INDEXER_PASSWORD=SecretPassword"
new_WZ_ADMIN_PASSWD="INDEXER_PASSWORD=${WZ_ADMIN_PASSWD}"
sed -i "s|${old_WZ_ADMIN_PASSWD}|${new_WZ_ADMIN_PASSWD}|g" docker-compose.yml
generate_hash
echo ""
read -p "Copy the hash value generated above, paste it here, and press 'Enter': " WZ_ADMIN_BCRYPT
echo ""
old_WZ_ADMIN_BCRYPT='$2y$12$K/SpwjtB.wOHJ/Nc6GVRDuc1h0rM1DfvziFRNPtk27P.c4yDr9njO'
new_WZ_ADMIN_BCRYPT="${WZ_ADMIN_BCRYPT}"
sed -i "s|${old_WZ_ADMIN_BCRYPT}|${new_WZ_ADMIN_BCRYPT}|g" config/wazuh_indexer/internal_users.yml
echo ""
apply_user_changes


echo ""
echo "========================================="
echo " CHANGE DEFAULT CREDENTIALS:KIBANASERVER "
echo "========================================="
echo ""
read -p "Type in the unique and complex password you made for your kibana dashboard user: " KIB_API_PASSWD
old_KIB_API_PASSWD="DASHBOARD_PASSWORD=kibanaserver"
new_KIB_API_PASSWD="DASHBOARD_PASSWORD=${KIB_API_PASSWD}"
sed -i "s|${old_KIB_API_PASSWD}|${new_KIB_API_PASSWD}|g" docker-compose.yml
echo ""
generate_hash
echo ""
read -p "Copy the hash value generated above, paste it here, and press 'Enter': " WZ_ADMIN_BCRYPT
echo ""
old_WZ_KIB_BCRYPT='$2a$12$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H.'
new_WZ_KIB_BCRYPT="${WZ_ADMIN_BCRYPT}"
sed -i "s|${old_WZ_KIB_BCRYPT}|${new_WZ_KIB_BCRYPT}|g" config/wazuh_indexer/internal_users.yml
echo ""
apply_user_changes


echo ""
echo "================================"
echo " CHANGE DEFAULT CREDENTIALS:API "
echo "================================"
echo ""
echo "Now we need to change the default password for your API"
echo ""
read -p "Type in the unique and complex password you made for your API: " WZ_API_PASSWD
echo ""
old_WZ_API_PASSWD="API_PASSWORD=MyS3cr37P450r.*-"
new_WZ_API_PASSWD="API_PASSWORD=${WZ_API_PASSWD}"
sed -i "s|${old_WZ_API_PASSWD}|${new_WZ_API_PASSWD}|g" docker-compose.yml
sed -i "s|${old_WZ_API_PASSWD}|${new_WZ_API_PASSWD}|g" config/wazuh_dashboard/wazuh.yml
echo "Once you press 'Enter' again, we will apply the API changes. This will mean recreating the containers. 
echo ""
echo "This will take 1-2mins"
echo ""
read -p "Press 'Enter' to continue..."
echo ""
docker compose down
echo ""
docker compose up -d

echo ""
docker ps

echo ""
echo "finis"
echo ""
