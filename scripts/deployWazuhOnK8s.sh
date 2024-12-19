#!/bin/bash
# deployWazuhOnK8s

# IN DEVELOPMENT DO NOT USE
# https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/kubernetes-deployment.html

git clone https://github.com/wazuh/wazuh-kubernetes.git -b v4.9.2 --depth=1
cd wazuh-kubernetes

kubectl apply -k envs/local-env/

kubectl get namespaces | grep wazuh

kubectl get deployments -n wazuh

kubectl get statefulsets -n wazuh

kubectl get pods -n wazuh

kubectl get services -o wide -n wazuh

kubectl -n wazuh port-forward --address <INTERFACE_IP_ADDRESS> service/dashboard 8443:443

kubectl exec -it wazuh-indexer-0 -n wazuh -- /bin/bash

echo -n "NewPassword" | base64

kubectl apply -k envs/local-env/

kubectl exec -it wazuh-indexer-0 -n wazuh -- /bin/bash

export INSTALLATION_DIR=/usr/share/wazuh-indexer
CACERT=$INSTALLATION_DIR/certs/root-ca.pem
KEY=$INSTALLATION_DIR/certs/admin-key.pem
CERT=$INSTALLATION_DIR/certs/admin.pem
export JAVA_HOME=/usr/share/wazuh-indexer/jdk