#!/bin/bash

# Function to check for errors
error_exit() {
  echo "[ERROR]: $1" >&2
  exit 1
}

# User Input for Variables
echo "Welcome to the NGINX Ingress setup script!"
read -p "Enter a namespace for the NGINX Ingress Controller (default: nginx-ingress): " NAMESPACE
NAMESPACE=${NAMESPACE:-nginx-ingress}

read -p "Enter the name for the NGINX Ingress deployment (default: nginx-ingress): " INGRESS_NAME
INGRESS_NAME=${INGRESS_NAME:-nginx-ingress}

read -p "Enter the port of your local web app (default: 8080): " LOCAL_APP_PORT
LOCAL_APP_PORT=${LOCAL_APP_PORT:-8080}

read -p "Enter the IP address of your local machine: " LOCAL_APP_IP
if [[ -z "$LOCAL_APP_IP" ]]; then
  error_exit "Local machine IP is required!"
fi

read -p "Enter the domain name to use for the Ingress (e.g., example.local): " DOMAIN_NAME
if [[ -z "$DOMAIN_NAME" ]]; then
  error_exit "Domain name is required!"
fi

INGRESS_CONFIG_FILE="/opt/ingress-config.yaml"

# Step 1: Create a namespace for NGINX Ingress
echo "Creating namespace '$NAMESPACE'..."
kubectl create namespace $NAMESPACE || error_exit "Failed to create namespace"

# Step 2: Deploy NGINX Ingress Controller using Helm
echo "Installing NGINX Ingress Controller using Helm..."
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx || error_exit "Failed to add Helm repo"
helm repo update || error_exit "Failed to update Helm repo"
helm install $INGRESS_NAME ingress-nginx/ingress-nginx --namespace $NAMESPACE || error_exit "Failed to install NGINX Ingress"

# Step 3: Wait for NGINX Ingress to be ready
echo "Waiting for NGINX Ingress Controller to be ready..."
kubectl wait --namespace $NAMESPACE --for=condition=available --timeout=300s deployment.apps/$INGRESS_NAME-ingress-nginx-controller || error_exit "NGINX Ingress Controller not ready"

# Step 4: Create an Ingress resource configuration
echo "Creating Ingress resource..."
cat <<EOF > $INGRESS_CONFIG_FILE
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: local-app-ingress
  namespace: $NAMESPACE
spec:
  rules:
  - host: $DOMAIN_NAME
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: local-app-service
            port:
              number: $LOCAL_APP_PORT
EOF

# Apply the Ingress configuration
kubectl apply -f $INGRESS_CONFIG_FILE || error_exit "Failed to create Ingress resource"

# Step 5: Expose your local app using a Kubernetes service
echo "Creating Service to expose local app..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: local-app-service
  namespace: $NAMESPACE
spec:
  ports:
    - protocol: TCP
      port: $LOCAL_APP_PORT
      targetPort: $LOCAL_APP_PORT
  externalIPs:
    - $LOCAL_APP_IP
EOF

# Completion message
echo "NGINX Ingress deployed successfully!"
echo "Access your app via http://$DOMAIN_NAME"