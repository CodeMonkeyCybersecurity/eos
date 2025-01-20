# Wazuh post install steps

Now we have installed Wazuh, we need to change the default passwords and verify it's working correctly before [exposing it to the internet](https://github.com/CodeMonkeyCybersecurity/hetcate.git).

Thank you to Wazuh for these [instructions](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html#change-pwd-existing-usr).

There are three default users whose passwords we need to change:
* Wazuh indexer users `admin` and `kibanaserver`
* Wazuh API user ``wazuh-wui` `

Again, thank you to Wazuh for the effort they put into their [documentation](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html).

## Changing default user passwords
We are going to be doing this in our `multi-node` cluster
```
cd $HOME/wazuh-docker/multi-node
```

#### Set a new hash
Stop the deployment stack if it’s running:
```
docker compose down
```

** Wazuh advises not to use the $ or & characters in your new password. These characters can cause errors during deployment. **  (see below)

Generate the new hash for your password

To do this, you will need the current version number in this format `<x.y.z>`. At the time of writing it is `4.10.1`. You can retreive the version number by checking `docker ps`. In the example below:
```
docker ps
```

Produces something like:
```
...
user@hostname:~$ docker ps
CONTAINER ID   IMAGE                          COMMAND                  CREATED        STATUS        PORTS                                                                            
75323ae7a33c   nginx:stable                   "/docker-entrypoint.…"   25 hours ago   Up 25 hours   80/tcp, 0.0.0.0:1514->1514/tcp, :::1514->1514/tcp                                                                                                     multi-node-nginx-1
7e80b8ed82c0   wazuh/wazuh-manager:4.10.1     "/init"                  25 hours ago   Up 25 hours   1514-1516/tcp, 514/udp, 55000/tcp                                                                                                                     multi-node-wazuh.worker-1
7ff51469f058   wazuh/wazuh-dashboard:4.10.1   "/entrypoint.sh"         25 hours ago   Up 25 hours   443/tcp, 0.0.0.0:5601->5601/tcp, :::5601->5601/tcp                                                                                                    multi-node-wazuh.dashboard-1
ca2349335431   wazuh/wazuh-manager:4.10.1     "/init"                  25 hours ago   Up 25 hours   1514/tcp, 0.0.0.0:1515->1515/tcp, :::1515->1515/tcp, 0.0.0.0:514->514/udp, :::514->514/udp, 1516/tcp, 0.0.0.0:55000->55000/tcp, :::55000->55000/tcp   multi-node-wazuh.master-1
b71c4d0ffe99   wazuh/wazuh-indexer:4.10.1     "/entrypoint.sh open…"   3 days ago     Up 3 days     9200/tcp                                                                                                                                              multi-node-wazuh3.indexer-1
af55260b6805   wazuh/wazuh-indexer:4.10.1     "/entrypoint.sh open…"   3 days ago     Up 3 days     0.0.0.0:9200->9200/tcp, :::9200->9200/tcp                                                                                                             multi-node-wazuh1.indexer-1
6767f086de3b   wazuh/wazuh-indexer:4.10.1     "/entrypoint.sh open…"   3 days ago     Up 3 days     9200/tcp                                                                                                                                              multi-node-wazuh2.indexer-1
...
```

Note the version is on the end over every Wazuh image name, eg. `wazuh/wazuh-indexer:4.10.1`

So input `4.10.1` when you are asked after running the code below
```
read -p "What is the current version number (in format x.y.z)?: " WAZUH_VERS
docker run --rm -ti wazuh/wazuh-indexer:${WAZUH_VERS} bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
```
#### Copy the generated hash
You will need to paste it into the next step.

##### Password complexity issues 
A side note:
Wazuh’s recommendation to avoid the “$” and “&” characters in new passwords stems from the way these symbols can be interpreted by shell scripts or deployment processes. Some examples with a bit more detail:
* Special Characters in Shell Scripts
* In most Unix-like shells, “$” is used to reference environment variables. For example, echo $HOME will display the current user’s home directory.
* “&” is often used to run processes in the background or to chain commands (e.g., command1 & command2).
When a password includes these symbols and is passed into scripts, they can be misread or cause parsing errors. For example, if the password is P@ss$word, the shell might interpret “$word” as a variable called word, leading to unexpected behavior.

This is also likely part of the reason that this warning comes up while setting the new password hash. You can safely ignore this.
```
**************************************************************************
** This tool will be deprecated in the next major release of OpenSearch **
** https://github.com/opensearch-project/security/issues/1755           **
**************************************************************************
```

### For `admin` 
#### Replace the hash.

Open the config/wazuh_indexer/internal_users.yml file. Locate the block for the user you are changing password for:

```
cd $HOME/wazuh-docker/multi-node
nano config/wazuh_indexer/internal_users.yml
```

* `admin` user
```
...
admin:
  hash: "$2y$12$K/SpwjtB.wOHJ/Nc6GVRDuc1h0rM1DfvziFRNPtk27P.c4yDr9njO"  # Replace this with the hash you copied
  reserved: true
  backend_roles:
  - "admin"
  description: "Demo admin user"
...
```


#### Set the new password
Now, open the `docker-compose.yml` file. Change all occurrences of the old *password* with the new *password*. Put it in plain text; don't put the hashed value in here. For example, for a multi-node deployment:

* `admin` user
```
cd $HOME/wazuh-docker/multi-node
nano docker-compose.yml
```

```
...
services:
  wazuh.manager:
    ...
    environment:
      - INDEXER_URL=https://wazuh.indexer:9200
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=SecretPassword  # Replace this with o
      - FILEBEAT_SSL_VERIFICATION_MODE=full
      - SSL_CERTIFICATE_AUTHORITIES=/etc/ssl/root-ca.pem
      - SSL_CERTIFICATE=/etc/ssl/filebeat.pem
      - SSL_KEY=/etc/ssl/filebeat.key
      - API_USERNAME=`wazuh-wui` 
      - API_PASSWORD=MyS3cr37P450r.*-
  ...
  wazuh.indexer:
    ...
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms1024m -Xmx1024m"
  ...
  wazuh.dashboard:
    ...
    environment:
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=SecretPassword  # Replace this
      - WAZUH_API_URL=https://wazuh.manager
      - DASHBOARD_USERNAME=kibanaserver
      - DASHBOARD_PASSWORD=kibanaserver
      - API_USERNAME=wazuh-wui
      - API_PASSWORD=MyS3cr37P450r.*-
  ...
```

#### Applying the changes
Start the deployment stack:
```
docker compose up -d
```
Run docker ps and note the name of the first Wazuh indexer container. For example, `multi-node-wazuh1.indexer-1`.

Run `docker exec -it <WAZUH_INDEXER_CONTAINER_NAME> bash` to enter the container. For example:
```
docker exec -it multi-node-wazuh1.indexer-1 bash
```

Set the following variables:
```
export INSTALLATION_DIR=/usr/share/wazuh-indexer
CACERT=$INSTALLATION_DIR/certs/root-ca.pem
KEY=$INSTALLATION_DIR/certs/admin-key.pem
CERT=$INSTALLATION_DIR/certs/admin.pem
export JAVA_HOME=/usr/share/wazuh-indexer/jdk
```

Wait for the Wazuh indexer to initialize properly. The waiting time can vary from two to five minutes. It depends on the size of the cluster, the assigned resources, and the speed of the network. Then, run the securityadmin.sh script to apply all changes.

Multi-node cluster
```
HOST=$(grep node.name $INSTALLATION_DIR/opensearch.yml | awk '{printf $2}')
bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert  $CACERT -cert $CERT -key $KEY -p 9200 -icl -h $HOST
```

Exit the Wazuh indexer container.
```
exit
```

You should now see your normal shell, something like:
```
...
user@hostname:~$
...
```

Now, login with the new credentials on the Wazuh dashboard. Verify they work before moving on.

### Repeat for `kibanaserver` 
You can only do one password change at a time, so make sure to restart the whole stack each time, before changing the password for the next default user.

Follow the steps outlined above under each of these headings:
#### Set a new hash
The version will remain unchanged from above:
```
read -p "What is the current version number (in format x.y.z)?: " WAZUH_VERS
docker run --rm -ti wazuh/wazuh-indexer:${WAZUH_VERS} bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
```

Copy the generated hash.

#### Replace the hash.

* `kibanaserver` user
```
cd $HOME/wazuh-docker/multi-node
nano config/wazuh_indexer/internal_users.yml
```

```
...
kibanaserver:
  hash: "$2a$12$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H."  # Replace this
  reserved: true
  description: "Demo kibanaserver user"
...
```

#### Set the new password
```
cd $HOME/wazuh-docker/multi-node
nano docker-compose.yml
```

```
...
services:
  wazuh.dashboard:
    ...
    environment:
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=ThisWillBeThePlainTextPasswordYouSetEarlier
      - WAZUH_API_URL=https://wazuh.manager
      - DASHBOARD_USERNAME=kibanaserver
      - DASHBOARD_PASSWORD=kibanaserver # Replace this
      - API_USERNAME=wazuh-wui
      - API_PASSWORD=MyS3cr37P450r.*-
  ...
```

#### Applying the changes
Start the deployment stack:
```
docker compose up -d
```

Because we're repeating the exact same steps as before, we 
```
docker exec -it multi-node-wazuh1.indexer-1 bash
```

We set these again:
```
export INSTALLATION_DIR=/usr/share/wazuh-indexer
CACERT=$INSTALLATION_DIR/certs/root-ca.pem
KEY=$INSTALLATION_DIR/certs/admin-key.pem
CERT=$INSTALLATION_DIR/certs/admin.pem
export JAVA_HOME=/usr/share/wazuh-indexer/jdk
```

Wait for the Wazuh indexer to initialize properly again for its two-five mins. Then again in the docker container:
```
HOST=$(grep node.name $INSTALLATION_DIR/opensearch.yml | awk '{printf $2}')
bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert  $CACERT -cert $CERT -key $KEY -p 9200 -icl -h $HOST
```

Before exitting the Wazuh indexer container.
```
exit
```

### Wazuh API users
The last default credentials we need to change are the default API credentials

The `wazuh-wui` user is the user to connect with the Wazuh API by default. Follow these steps to change the password.

Note The password for Wazuh API users must be between 8 and 64 characters long. It must contain at least one uppercase and one lowercase letter, a number, and a symbol.
Open the file config/wazuh_dashboard/wazuh.yml and modify the value of password parameter.
```
cd $HOME/wazuh-docker/multi-node
nano config/wazuh_dashboard/wazuh.yml
```

```
...
hosts:
  - 1513629884013:
      url: "https://wazuh.manager"
      port: 55000
      username: wazuh-wui
      password: "MyS3cr37P450r.*-" # Replace this
      run_as: false
...
```

Open the `docker-compose.yml` file. Change all occurrences of the old password with the new one.
```nano docker-compose.yml```

```
...
services:
  wazuh.manager:
    ...
    environment:
      - INDEXER_URL=https://wazuh.indexer:9200
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=ThisWillBeThePlainTextPasswordYouSetEarlier
      - FILEBEAT_SSL_VERIFICATION_MODE=full
      - SSL_CERTIFICATE_AUTHORITIES=/etc/ssl/root-ca.pem
      - SSL_CERTIFICATE=/etc/ssl/filebeat.pem
      - SSL_KEY=/etc/ssl/filebeat.key
      - API_USERNAME=`wazuh-wui` 
      - API_PASSWORD=MyS3cr37P450r.*- # Replace this
  ...
  wazuh.dashboard:
    ...
    environment:
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=ThisWillBeThePlainTextPasswordYouSetEarlier
      - WAZUH_API_URL=https://wazuh.manager
      - DASHBOARD_USERNAME=kibanaserver
      - DASHBOARD_PASSWORD=ThisIsTheOtherPasswordYouSetEarlier
      - API_USERNAME=`wazuh-wui` 
      - API_PASSWORD=MyS3cr37P450r.*- # Replace this
  ...
```

Recreate the Wazuh containers:

```
docker-compose down
docker-compose up -d
```

### Note 
Docker doesn’t reload the configuration dynamically. You need to restart the stack after changing the configuration of a component.
