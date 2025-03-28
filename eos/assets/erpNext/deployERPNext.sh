#!/bin/bash
# deployERPNext.sh

git clone https://github.com/frappe/frappe_docker
cd frappe_docker
docker compose -f pwd.yml up -d

docker ps

echo "finis"
