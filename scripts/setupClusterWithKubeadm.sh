#!/bin/bash
set -x
ip route show 
echo "Look for a line starting with "default via"
echo "instructions on https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/"
set +x
echo "finis"