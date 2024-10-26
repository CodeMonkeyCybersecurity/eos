sudo apt update && sudo apt dist-upgrade -y
cd ~/
sudo curl https://packages.hetzner.com/hcloud/deb/hc-utils_0.0.4-1_all.deb -o /tmp/hc-utils_0.0.3-1_all.deb -s && apt install /tmp/hc-utils_0.0.3-1_all.deb
