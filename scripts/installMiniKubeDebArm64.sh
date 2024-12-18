#!/bin/bash

echo "curl-ing minikube from https://storage.googleapis.com/minikube/releases/latest/minikube_latest_arm64.deb"
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube_latest_arm64.deb

echo "installing minikube"
sudo dpkg -i minikube_latest_arm64.deb

echo "starting minikube"
minikube start

echo "finis"
