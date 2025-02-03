#!/bin/bash
# deployMattermost.sh

echo "instructions https://docs.mattermost.com/install/install-docker.html#deploy-mattermost-on-docker-for-production-use"

echo "clone the repository and enter the directory."
git clone https://github.com/mattermost/docker
cd docker

echo "Create your .env file by copying and adjusting the env.example file."
echo "At a minimum, you must edit the DOMAIN value in the .env file to correspond to the domain for your Mattermost server."
cp env.example .env

echo "Create the required directories and set their permissions."
mkdir -p ./volumes/app/mattermost/{config,data,logs,plugins,client/plugins,bleve-indexes}
sudo chown -R 2000:2000 ./volumes/app/mattermost

echo "deploy mattermost without nginx. Hecate will be your reverse proxy"
sudo docker compose -f docker-compose.yml -f docker-compose.without-nginx.yml up -d

echo "verify you can access 'http://localhost:8065'"
