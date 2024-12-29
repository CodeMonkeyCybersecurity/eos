sudo ufw allow 10443
sudo ufw allow 25000:25010/tcp && sudo ufw reload


# https://microk8s.io/docs/getting-started
sudo snap install microk8s --classic
sudo usermod -a -G microk8s $USER
sudo chown -R henry ~/.kube
mkdir -p ~/.kube
chmod 0700 ~/.kube
newgrp microk8s

sudo microk8s status --wait-ready

sudo microk8s enable dashboard
sudo microk8s enable dns
sudo microk8s enable registry
sudo microk8s enable istio
sudo microk8s enable ingress


sudo microk8s kubectl get all --all-namespaces

sudo microk8s dashboard-proxy

exit # to allow for permissions chagens above to take effect


-------------
# https://microk8s.io/docs/how-to-ceph
sudo snap install microceph --channel=latest/edge
sudo microceph cluster bootstrap
sudo microceph.ceph status                                                                                                                                                                                        
sudo microceph disk list                                                                    
sudo microk8s enable rook-ceph
sudo microk8s connect-external-ceph

