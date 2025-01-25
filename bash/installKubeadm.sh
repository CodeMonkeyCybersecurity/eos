sudo apt update

nc 127.0.0.1 6443 -v
sudo ufw allow 6443
sudo ufw reload
nc 127.0.0.1 6443 -v

sudo apt install -y apt-transport-https ca-certificates curl

curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list

sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl containerd
sudo apt-mark hold kubelet kubeadm kubectl
sudo systemctl enable kubelet

sudo systemctl enable --now kubelet

sudo swapoff -a 
sudo apt install -y cri-tools



echo "Check that kubectl is properly configured by getting the cluster state:"
kubectl cluster-info

echo "openning: 'sudo nano /etc/fstab'"
echo "Look for a line like this:"
echo "/swapfile swap swap defaults 0 0"
echo "#/swapfile swap swap defaults 0 0"
sudo nano /etc/fstab

sudo kubeadm init --control-plane-endpoint=188.245.110.59:6443 --pod-network-cidr=192.168.0.0/16

mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

sudo systemctl restart kubelet
sudo crictl ps




kubectl get nodes
kubectl get pods -n kube-system




https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/
 ip route show