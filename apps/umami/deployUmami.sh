#!/bin/bash
# deployUmami.sh

echo "instructions from 'https://umami.is/docs/install'"

echo "Install Yarn"
sudo npm install -g yarn

echo "Get the source code and install packages"
git clone https://github.com/umami-software/umami.git
cd umami
yarn install

echo "Configure Umami"
echo "Configure Umami
Create an .env file with the following
DATABASE_URL={connection url}
The connection url is in the following format:
DATABASE_URL=postgresql://username:mypassword@localhost:5432/mydb"

echo "install with Docker"
docker compose up -d
