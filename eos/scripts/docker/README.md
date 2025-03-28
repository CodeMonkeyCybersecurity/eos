# Installing docker 

I like installing docker via snap
```
sudo snap install docker
```

You then need to complete the post install instructions for docker:
Instructions for the post-install steps for docker are from here https://docs.docker.com/engine/install/linux-postinstall/
```
# To create the docker group and add your user:
# Create the docker group.
sudo groupadd docker

# Add your user to the docker group.
sudo usermod -aG docker $USER

#You can also run the following command to activate the changes to groups:
newgrp docker
```

Verify that you can run docker commands without sudo.
```
docker run hello-world 
```
