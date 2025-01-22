sudo ufw allow 10443
sudo ufw allow 25000:25010/tcp && sudo ufw reload


# https://microk8s.io/docs/getting-started
sudo snap install microk8s --classic
sudo usermod -a -G microk8s henry
sudo chown -R henry ~/.kube
newgrp microk8s
alias kubectl='microk8s kubectl'

sudo microk8s status --wait-ready


sudo microk8s enable dashboard dns rbac registry  istio rook-ceph
sudo microk8s enable ingress

sudo microk8s kubectl get all --all-namespaces

sudo microk8s dashboard-proxy





-----------------------
microk8s kubectl describe secret -n kube-system microk8s-dashboard-token