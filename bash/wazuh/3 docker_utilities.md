# Wazuh Docker utilities
[Credit once again](https://documentation.wazuh.com/current/deployment-options/docker/container-usage.html)
After installing the Wazuh-Docker containers, there are several tasks you can do to benefit the most from your Wazuh installation.

## Access to services and containers
Access the Wazuh dashboard using the Docker host IP address. For example, https://localhost, if you are on the Docker host.

Note In case you use a self-signed certificate, your browser will warn that it cannot verify its authenticity.
Enroll the agents by following the standard enrollment process and using the Docker host address as the manager address. For more information, see the Wazuh agent enrollment documentation.

List the containers in the directory where the Wazuh docker-compose.yml file is located:
```
cd $HOME/wazuh-docker/multi-node
docker compose ps
```

Output
```
multi-node-nginx-1             nginx:stable                   "/docker-entrypoint.…"   nginx               7 minutes ago       Up 7 minutes        80/tcp, 0.0.0.0:1514->1514/tcp, :::1514->1514/tcp
multi-node-wazuh.dashboard-1   wazuh/wazuh-dashboard:4.10.0   "/entrypoint.sh"         wazuh.dashboard     7 minutes ago       Up 7 minutes        443/tcp, 0.0.0.0:5601->5601/tcp, :::5601->5601/tcp
multi-node-wazuh.master-1      wazuh/wazuh-manager:4.10.0     "/init"                  wazuh.master        7 minutes ago       Up 7 minutes        1514/tcp, 0.0.0.0:1515->1515/tcp, :::1515->1515/tcp, 0.0.0.0:514->514/udp, :::514->514/udp, 1516/tcp, 0.0.0.0:55000->55000/tcp, :::55000->55000/tcp
multi-node-wazuh.worker-1      wazuh/wazuh-manager:4.10.0     "/init"                  wazuh.worker        7 minutes ago       Up 7 minutes        1514-1516/tcp, 514/udp, 55000/tcp
multi-node-wazuh1.indexer-1    wazuh/wazuh-indexer:4.10.0     "/entrypoint.sh open…"   wazuh1.indexer      7 minutes ago       Up 7 minutes        0.0.0.0:9200->9200/tcp, :::9200->9200/tcp
multi-node-wazuh2.indexer-1    wazuh/wazuh-indexer:4.10.0     "/entrypoint.sh open…"   wazuh2.indexer      7 minutes ago       Up 7 minutes        9200/tcp
multi-node-wazuh3.indexer-1    wazuh/wazuh-indexer:4.10.0     "/entrypoint.sh open…"   wazuh3.indexer      7 minutes ago       Up 7 minutes        9200/tcp
```

Run the command below from the directory where the docker-compose.yml file is located to access the command line of each container:


docker-compose exec <SERVICE> bash
Wazuh service data volumes
You can set Wazuh configuration and log files to exist outside their containers. This allows the files to persist after removing containers, and you can provision custom configuration files to your containers.

You need multiple volumes to ensure persistence on a Wazuh container. The following is an example of a docker-compose.yml with persistent volumes:


services:
  wazuh:
    . . .
    volumes:
      - wazuh_api_configuration:/var/ossec/api/configuration

volumes:
  wazuh_api_configuration:
You can list persistent volumes with docker volume ls:

Output
DRIVER              VOLUME NAME
local               single-node_wazuh_api_configuration
Storage volume for Wazuh indexer and dashboard
Attaching a volume for the storage of Wazuh indexer data is also possible. By default, the single-node and multi-node deployments already have volumes configured. An example of a single-node wazuh indexer volume is shown in the docker-compose.yml below:


wazuh.indexer:
    . . .
     volumes:
       - wazuh-indexer-data:/var/lib/wazuh-indexer

    . . .

volumes:
  wazuh-indexer-data
Custom commands and scripts
To execute commands in the Wazuh manager container, you can execute a shell:


docker exec -it single-node-wazuh.manager-1 bash
Every change made on this shell persists as long as you have the data volumes configured correctly.

Wazuh Docker deployment
Upgrading Wazuh Docker
Explore
Overview
XDR
SIEM
