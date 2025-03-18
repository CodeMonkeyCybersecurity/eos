#!/bin/bash
# shutdownMattermost.sh

cd docker
sudo docker compose -f docker-compose.yml -f docker-compose.without-nginx.yml down
