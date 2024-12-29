sudo ufw allow 10443
sudo ufw allow 25000:25010/tcp && sudo ufw reload


# https://microk8s.io/docs/getting-started
sudo snap install microk8s --classic
sudo usermod -a -G microk8s $USER
mkdir -p ~/.kube
chmod 0700 ~/.kube
su - $USER

sudo microk8s status --wait-ready

sudo microk8s enable dashboard
sudo microk8s enable dns
sudo microk8s enable registry
sudo microk8s enable istio
sudo microk8s enable ingress

sudo microk8s kubectl get all --all-namespaces

sudo microk8s dashboard-proxy


----------
https://snapcraft.io/install/microceph/ubuntu
sudo snap install microceph
 sudo snap refresh --hold microceph
 sudo microceph cluster bootstrap
 sudo microceph disk add loop,4G,3
 sudo ceph status
 kubectl apply -f https://raw.githubusercontent.com/ceph/ceph-csi/devel/examples/kubernetes/cephfs/driver.yaml











 --------------
 henry@vhost1:~$ sudo microk8s status
microk8s is running
high-availability: no
  datastore master nodes: 100.122.41.58:19001
  datastore standby nodes: none
addons:
  enabled:
    dashboard            # (core) The Kubernetes dashboard
    dns                  # (core) CoreDNS
    ha-cluster           # (core) Configure high availability on the current node
    helm                 # (core) Helm - the package manager for Kubernetes
    helm3                # (core) Helm 3 - the package manager for Kubernetes
    hostpath-storage     # (core) Storage class; allocates storage from host directory
    ingress              # (core) Ingress controller for external access
    metrics-server       # (core) K8s Metrics Server for API access to service metrics
    registry             # (core) Private image registry exposed on localhost:32000
    storage              # (core) Alias to hostpath-storage add-on, deprecated
  disabled:
    cert-manager         # (core) Cloud native certificate management
    cis-hardening        # (core) Apply CIS K8s hardening
    community            # (core) The community addons repository
    gpu                  # (core) Alias to nvidia add-on
    host-access          # (core) Allow Pods connecting to Host services smoothly
    kube-ovn             # (core) An advanced network fabric for Kubernetes
    mayastor             # (core) OpenEBS MayaStor
    metallb              # (core) Loadbalancer for your Kubernetes cluster
    minio                # (core) MinIO object storage
    nvidia               # (core) NVIDIA hardware (GPU and network) support
    observability        # (core) A lightweight observability stack for logs, traces and metrics
    prometheus           # (core) Prometheus operator for monitoring and logging
    rbac                 # (core) Role-Based Access Control for authorisation
    rook-ceph            # (core) Distributed Ceph storage using Rook