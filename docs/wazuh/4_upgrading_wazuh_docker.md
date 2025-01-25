## Upgrading Wazuh Docker
Official instructions [here](https://documentation.wazuh.com/current/deployment-options/docker/upgrading-wazuh-docker.html#keeping-custom-docker-compose-files)

This section describes how to upgrade your Wazuh Docker deployment, starting from version 4.3.

To upgrade to version 4.10, you can follow one of two strategies.

#### Using default docker compose files : 
This strategy uses the default docker compose files for Wazuh 4.10. It replaces the docker compose files of your outdated Wazuh version.

#### Keeping custom docker compose files : 
This strategy preserves the docker compose files of your outdated Wazuh deployment. It ignores the docker compose files of the latest Wazuh version.

### Using default docker compose files
Run the following command from your wazuh-docker directory, such as `wazuh-docker/single-node/` or `wazuh-docker/multi-node/`, to stop the outdated environment:
```
cd $HOME/wazuh-docker/multi-node/
docker compose down
```

Checkout the tag for the current version of wazuh-docker:
```
git checkout v4.10.1
```

Start the new version of Wazuh using docker compose:
```
docker compose up -d
```

### Keeping custom docker compose files
To upgrade your deployment keeping your custom docker compose files, do the following.

Run the following command from your wazuh-docker directory, such as `wazuh-docker/single-node/` or `wazuh-docker/multi-node/`, to stop the outdated environment:

```
docker compose down
```

If you are upgrading from a version earlier than 4.8, update the defaultRoute parameter in the Wazuh dashboard configuration. If you are not, skip onto the next step where you modify `OPENSEARCH_JAVA_OPTS`

Because we are using a Multi node deployment
```
nano multi-node/config/wazuh_dashboard/opensearch_dashboards.yml
```
And update this value
```
uiSettings.overrides.defaultRoute: /app/wz-home
```

Modify the `OPENSEARCH_JAVA_OPTS` environment variable to allocate more RAM to the Wazuh indexer container.

Multi node deployment
```
nano multi-node/docker compose.yml
```
```
...
environment:
- "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
...
```

Modify the the tag of image generator.

Multi node deployment
```
nano multi-node/generate-indexer-certs.yml
```
```
...
services:
   generator:
      image: wazuh/wazuh-certs-generator:0.0.2
...
```

After these steps, if you needed to make changes, you need to recreate the certificates.
If you didn't make any changes, you don't need to recreate certificates.
```
docker compose -f generate-indexer-certs.yml run --rm generator
```

If you are upgrading from 4.3, update old paths with the new ones. See wazuh's documentation linked above

Edit the docker-compose.yml file corresponding to your deployment type. Modify the highlighted lines and add the variable related to the kibanaserver user with the corresponding value.

Multi node deployment
```
nano docker-compose.yml
```
```
wazuh.master:
   image: wazuh/wazuh-manager:4.10.1
...
wazuh.worker:
   image: wazuh/wazuh-manager:4.10.1
...
wazuh1.indexer:
   image: wazuh/wazuh-manager:4.10.1
...
wazuh2.indexer:
   image: wazuh/wazuh-manager:4.10.1
...
wazuh3.indexer:
   image: wazuh/wazuh-manager:4.10.1
...
wazuh.master:
   image: wazuh/wazuh-manager:4.10.1
   environment:
      - OPENSEARCH_HOSTS="https://wazuh1.indexer:9200"
      - WAZUH_API_URL="https://wazuh.master"
      - API_USERNAME=wazuh-wui
      - API_PASSWORD=MyS3cr37P450r.*-
      - DASHBOARD_USERNAME=kibanaserver
      - DASHBOARD_PASSWORD=kibanaserver
```
Replace the following files in your deployment with the ones from the v4.10.1 tag of the wazuh-docker repository.

Single node deploymentMulti node deployment
```
cd $HOME/wazuh-docker/multi-node
nano config/wazuh_cluster/wazuh_manager.conf
```
then,
```
multi-node/config/wazuh_cluster/wazuh_worker.conf
```

Start the new version of Wazuh using docker compose.
```
docker compose up -d
```

Next, FAQs 
