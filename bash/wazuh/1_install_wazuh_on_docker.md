# Installing Wazuh on a local backend in a docker container
This is how to install Wazuh in a docker container in a way that, once a remote reverse proxy is set up, will be accessible from the internet. If you are wanting to expose Wazuh to the internet, these instructions need to be read alongside the [hecate reverse proxy instructions](https://github.com/CodeMonkeyCybersecurity/hecate.git).

Up to date instructions for all of this are available [on Wazuh's website](https://documentation.wazuh.com/current/deployment-options/docker/index.html).

## Make sure docker is installed
**If docker is not installed, you can follow [these](https://github.com/CodeMonkeyCybersecurity/eos/tree/main/legacy/docker) instructions**

### Docker modification
* Prior to installing Wazuh, you need to increase max_map_count on your Docker host
```
sysctl -w vm.max_map_count=262144
```

## For a single node deployment 
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

This install location assumes you will be the one administering the wazuh install because it is being installed in your home directory.


### Generate self-signed certificates for each cluster node.

We have created a Docker image to automate certificate generation using the Wazuh certs gen tool.

If your system uses a proxy (such as [hecate](https://github.com/CodeMonkeyCybersecurity/hecate.git)) , add the following to the generate-indexer-certs.yml file.

As a reminder, if you are using Wazuh alongside other web applications, you need to install wazuh on a subdomain. For example, if your main domain is `domain.com`, wazuh will need to be on a subdomain such as `wazuh.domain.com`. If you want to install it in a location like domain.com/wazuh, you need to rewite a whole bunch of javascript. [Hecate](https://github.com/CodeMonkeyCybersecurity/hecate.git) provides a template for installing Wazuh fairly painlessly.

```
environment:
  - HTTP_PROXY=YOUR_PROXY_ADDRESS_OR_DNS
```

To do this, go to:
```
cd $HOME/wazuh-docker/single-node
nano generate-indexer-certs.yml
```
Paste this at the bottom of the file
```
    environment:
      - HTTP_PROXY=wazuh.domain.com
```

You can check your yaml syntax [here](https://www.yamllint.com/).

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
      - HTTP_PROXY=wazuh.domain.com
```

Create the desired certificates:
```
cd $HOME/wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
```

### Exposing the correct ports on the backed 
Make sure your tailscale network is up on your computer, your backend server, and your reverse proxy.

#### To allow the appropriate firewall rules (recommended approach):
To read about ufw firewall rules, go here https://help.ubuntu.com/community/UFW

```
# check current status
sudo ufw status

# for ssh
sudo ufw allow from <your tailscale IP> to any port 22 proto tcp # recommended

# for web server 
sudo ufw allow from <reverse proxy tailscale IP> to any port 80,443 proto tcp # recommended

# for wazuh
sudo ufw allow from <reverse proxy tailscale IP> to any port 1514,1515,5601,55000,9200 proto tcp # recommended

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
# check current status
sudo ufw status

# for ssh
sudo ufw allow ssh

# for web server 
sudo ufw allow http
sudo ufw alllow https

# for wazuh
sudo ufw allow from any to any port 1514,1515,5601,55000,9200 proto tcp

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
cd $HOME/wazuh-docker/single-node
nano docker-compose.yml
```

Navigate to this section
```
...
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
...
```

And change it to 
```
...
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
...
```

### Start up wazuh in docker
Start it up 
```
cd $HOME/wazuh-docker/single-node
docker compose up -d
```

### Verify your install 
Check the docker containers are running
```
docker ps
```

### Access via the browser
Access wazuh instance locally via browser: `https://<backend tailscale IP>:5601`

You should see your Wazuh login page available here.

### Securing your install
#### The oldest vulnerability in the world is default credentials, so make sure you change them
Please see the Wazuh documentation [here](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html) for changing default passwords etc.

#### Install fail2ban
```
sudo apt update
sudo apt install fail2ban
```

### Establishing reverse proxy
**This should only be done after you are comfortable with the security of your install**
Once you expose your install via reverse proxy it is exposed to the internet.
The internet is a wild place AND IF YOU DONT SECURE IT PROPERLY YOU ARE POTENTIALLY INVITING THE WHOLE INTERNET INTO YOUR LOCAL LAN. NOT A GOOD IDEA.

If you are comfortable with the security of your install, proceed to enabling the reverse proxy by going to our reverse proxy repo, [Hecate](https://github.com/CodeMonkeyCybersecurity/hecate).

If you are going to do this, please make sure to change the default passwords *before* eposing it to the internet. For how to do this, please see [post install steps](https://github.com/CodeMonkeyCybersecurity/eos/edit/main/legacy/wazuh/postInstallSteps.md).


### Exposed ports
By default, the stack exposes the following ports:

| Port | Protocol   |       
| ------| ----------- |
1514    | Wazuh TCP |
1515    | Wazuh TCP |
514     | Wazuh UDP |
55000   | Wazuh API |
9200    | Wazuh indexer HTTPS |
443     | Wazuh dashboard HTTPS |


Next: [Change default passwords](https://github.com/CodeMonkeyCybersecurity/eos/blob/main/bash/wazuh/2_change_default_passwds.md)
