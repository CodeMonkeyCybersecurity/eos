#!/bin/bash

sudo zpool status
read -p "what is the name of the zpool you want to remove: " POOLNAME
sudo zpool destroy $POOLNAME
sudo zpool status
echo "done"
