# How to install a kubernetes cluster?

## We find the easiest way is using [k3s](https://k3s.io)
```
curl -sfL https://get.k3s.io | sh - 
# Check for Ready node, takes ~30 seconds 
sudo k3s kubectl get node 
```

Can also check the pods are running 
```
sudo kubectl get pods -n kube-system
```
