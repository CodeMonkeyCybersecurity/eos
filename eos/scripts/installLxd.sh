 #!/bin/bash

 sudo apt update 

 sudo apt install -y snap snapd

 sudo snap install lxd --channel=latest/stable

# If you want the current user to be able to interact with the LXD daemon, add it to the lxd group as the installation process does not add it for you:
 getent group lxd | grep -qwF "$USER" || sudo usermod -aG lxd "$USER"

 echo "done"
