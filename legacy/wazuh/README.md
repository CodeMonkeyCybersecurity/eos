# Installing Wazuh on a local backend in a docker container
This is how to install Wazuh in a docker container in a way that, once a remote reverse proxy is set up, will be accessible from the internet 

## Make sure docker is installed
**If docker is already installed, you can skip these instructions**

* Increase max_map_count on your Docker host
```
sysctl -w vm.max_map_count=262144
```

* I like installing docker via snap
```
sudo snap install docker
```

* You then need to complete the post install instructions for docker:
Instructions for the post-install steps for docker are from here https://docs.docker.com/engine/install/linux-postinstall/

```
# To create the docker group and add your user:
# Create the docker group.
sudo groupadd docker

# Add your user to the docker group.
sudo usermod -aG docker $USER

#You can also run the following command to activate the changes to groups:
newgrp docker
```

Verify that you can run docker commands without sudo.
```
docker run hello-world 
```

## For a single node deployment 
Up to date instructions are available at https://documentation.wazuh.com/current/deployment-options/docker/index.html

### Navigate to your home directory and clone the repository
Clone the repo into a good directory to install it:
```
cd $HOME
git clone https://github.com/wazuh/wazuh-docker.git -b v4.10.0
cd $HOME/wazuh-docker/single-node

# verify the present working direcotry (pwd) is cd $HOME/wazuh-docker/single-node
pwd
echo "verify the present working direcotry (pwd) is cd $HOME/wazuh-docker/single-node"
```

This install location assumes you will be the one administering the wazuh install.


### Generate self-signed certificates for each cluster node.

We have created a Docker image to automate certificate generation using the Wazuh certs gen tool.

If your system uses a proxy, add the following to the generate-indexer-certs.yml file.

```
environment:
  - HTTP_PROXY=YOUR_PROXY_ADDRESS_OR_DNS
```

To do this, go to:
```
cd /opt/wazuh-docker/single-node
nano generate-indexer-certs.yml
```
Paste this at the bottom of the file
```
    environment:
      - HTTP_PROXY=wazuh.domain.com
```
**Make sure your indentation is correct**

You can check your yaml syntax at: `https://www.yamllint.com/`

The complete example looks like:
```
# Wazuh App Copyright (C) 2017 Wazuh Inc. (License GPLv2)
version: '3'

services:
  generator:
    image: wazuh/wazuh-certs-generator:0.0.2
    hostname: wazuh-certs-generator
    volumes:
      - ./config/wazuh_indexer_ssl_certs/:/certificates/
      - ./config/certs.yml:/config/certs.yml
    environment:
      - HTTP_PROXY=domain.com
```

Create the desired certificates:
```
cd $HOME/wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
```

### Exposing the correct ports on the backed 
Make sure your tailscale network is up on your computer, your backend server, and your reverse proxy.

#### To allow the appropriate firewall rules (recommended approach):
```
# check current status
sudo ufw status

# for ssh
sudo ufw allow from <your tailscale IP> to any port 22 # recommended

# for web server 
sudo ufw allow from <reverse proxy tailscale IP> to any port 80,443 # recommended

# for wazuh
sudo ufw allow from <reverse proxy tailscale IP> to any port 1514,1515,5601,55000,9200 # recommended

# reload the firewall
sudo ufw reload

# check current status
sudo ufw status
```

check that has all worked
```
sudo ufw status
```

If it has, enable the ufw 
```
sudo ufw enable
```

#### Less likely to run into issues, but also less secure
```
sudo ufw status

# for ssh
sudo ufw allow 22

# for web server 
sudo ufw allow 80,443

# for wazuh
sudo ufw allow 1514,1515,5601,55000,9200

# reload the firewall
sudo ufw reload
```

check that has all worked
```
sudo ufw status
```

If it has, enable the ufw 
```
sudo ufw enable
```

### Adjusting the default `docker-compose.yml`
I also recommend adjusting the `docker-compose.yml` file to expose the desktop via port 5601 beccause if you are hosting multiple services on the one local backend, then port 443 (the default port that wazuh exposes) can cause issues.

To do this, open up docker-compose.yml:
```
cd /opt/wazuh-docker/single-node
nano docker-compose.yml
```

Navigate to this section
```
  wazuh.dashboard:
    image: wazuh/wazuh-dashboard:4.10.0
    hostname: wazuh.dashboard
    restart: always
    ports:
      - 443:5601
    environment:
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=SecretPassword
      - WAZUH_API_URL=https://wazuh.manager
      - DASHBOARD_USERNAME=kibanaserver
      - DASHBOARD_PASSWORD=kibanaserver
      - API_USERNAME=wazuh-wui
      - API_PASSWORD=MyS3cr37P450r.*-
```

And change it to 
```
  wazuh.dashboard:
    image: wazuh/wazuh-dashboard:4.10.0
    hostname: wazuh.dashboard
    restart: always
    ports:
      - 5601:5601 # Now exposing dashboard to 5601
    environment:
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=SecretPassword
      - WAZUH_API_URL=https://wazuh.manager
      - DASHBOARD_USERNAME=kibanaserver
      - DASHBOARD_PASSWORD=kibanaserver
      - API_USERNAME=wazuh-wui
      - API_PASSWORD=MyS3cr37P450r.*-
```

### Start up wazuh in docker
Start it up 
```
cd /opt/wazuh-docker/single-node
docker compose up -d
```

### Securing it
#### The oldest vulnerability in the world is default credentials, so make sure you change them
Please see the Wazuh documentation at: https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html for changing default passwords etc.

#### Install fail2ban
```
sudo apt update
sudo apt install fail2ban
```




