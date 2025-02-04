#!/bin/bash
# deployMailcow.sh

echo "Install mailcow"
git clone https://github.com/mailcow/mailcow-dockerized
cd mailcow-dockerized

echo "Generate a configuration file. Use a FQDN (host.domain.tld) as hostname when asked."
./generate_config.sh

echo "Change configuration if you want or need to."
nano mailcow.conf

echo "Start mailcow"
docker compose pull
docker compose up -d

docker ps

echo "You can now access https://${MAILCOW_HOSTNAME} with the default credentials" 
echo "username:"
echo "admin" 
echo "password:" 
echo "moohoo"

