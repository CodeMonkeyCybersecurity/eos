#!/bin/bash
# refreshMattermost.sh

cd docker


sudo docker compose -f docker-compose.yml -f docker-compose.without-nginx.yml up -d

echo "finis"
