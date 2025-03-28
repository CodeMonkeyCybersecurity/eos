#!/bin/bash
# removeWazuh.sh

su 

cd /opt

cd wazuh-docker/multi-node
docker compose down -v

cd ../single-node
docker compose down -v

docker ps
read -p "Press enter to continue..."

cd ../..
sudo rm -rf wazuh-docker

echo "finis"
