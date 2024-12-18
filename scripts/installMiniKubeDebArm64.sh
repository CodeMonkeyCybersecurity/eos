#!/bin/bash

set -x

echo "Starting system update and cleanup..."
apt update && apt dist-upgrade -y && apt autoremove -y && apt autoclean -y
checkCommand "System update and cleanup"

echo "curl-ing minikube from https://storage.googleapis.com/minikube/releases/latest/minikube_latest_arm64.deb"
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube_latest_arm64.deb

echo "installing minikube"
sudo dpkg -i minikube_latest_arm64.deb

echo "starting minikube"
minikube start

# Function to validate yes/no input
function yesNoPrompt() {
    while true; do
        read -p "$1 (y/n): " choice
        case "$choice" in
            y|Y ) return 0 ;;  # Yes
            n|N ) return 1 ;;  # No
            * ) echo "Invalid input. Please enter y or n." ;;
        esac
    done
}

echo "finis"

function deployTestService() {
    if yesNoPrompt "Do you want to deploy a hello-minikube test service?"; then 
        echo "Running 'kubectl create deployment hello-minikube --image=kicbase/echo-server:1.0'"
        kubectl create deployment hello-minikube --image=kicbase/echo-server:1.0
        echo "Running 'kubectl expose deployment hello-minikube --type=NodePort --port=8080'"
        kubectl expose deployment hello-minikube --type=NodePort --port=8080
        echo "Running 'kubectl get services hello-minikube'"
	kubectl get services hello-minikube
	echo "Running 'kubectl port-forward service/hello-minikube 7080:8080'"
	kubectl port-forward service/hello-minikube 7080:8080
	echo "your app should now be available at http://hostname:7080/"
    else 
        echo "hello-minikube test service not deployed. Moving on..."
    fi
}

function deployLoadBalance() {
    if yesNoPrompt "Do you want to access a LoadBalancer deployment, using the “minikube tunnel” command?"; then
        kubectl create deployment balanced --image=kicbase/echo-server:1.0
        kubectl expose deployment balanced --type=LoadBalancer --port=8080
        echo "In another window, start the tunnel to create a routable IP for the ‘balanced’ deployment:"
        echo "minikube tunnel"
        echo "To find the routable IP, run this command and examine the EXTERNAL-IP column:"
        echo "kubectl get services balanced"
        echo "Your deployment is now available at <EXTERNAL-IP>:8080"
    else 
        echo "Not deploying load balancer. Moving on..."
    fi
}

function deployIngress() {
    if yesNoPrompt "Do you want to enable the ingress addon?"; then
        minikube addons enable ingress
    else 
        echo "ingress not enabled"
    fi
}

function startKube() {
    if yesNoPrompt "Do you want start minikube?"; then
        minikube start
    else 
        echo "minikube not started"
    fi
}

deployTestService
deployLoadBalance
deployIngress
startKube

echo "finis"

set +x