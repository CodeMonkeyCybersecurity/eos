
sudo snap install openstack --channel 2024.1/beta
sudo snap install --channel 3.6/stable juju
sudo snap install lxd
newgrp lxd
lxd init

lxc list
lxc storage list
lxc network list


sudo apt install -y curl cpu-checker

sudo ufw allow in on lxdbr0 sudo ufw allow out on lxdbr0 sudo ufw reload

juju bootstrap localhost --debug
