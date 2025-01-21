#!/bin/bash

# https://canonical-microcloud.readthedocs-hosted.com/en/stable/microcloud/tutorial/get_started/





root@micro1:~# snap install microceph --channel=squid/stable --cohort="+"
snap install microovn --channel=24.03/stable --cohort="+"
snap install microcloud --channel=2/stable --cohort="+"
microceph (squid/stable) 19.2.0+snap9aeaeb2970 from Canonical✓ installed
snap "microovn" is already installed, see 'snap help refresh'
snap "microcloud" is already installed, see 'snap help refresh'
root@micro1:~# microcloud init
Waiting for services to start ...
Do you want to set up more than one cluster member? (yes/no) [default=yes]:
Using address "10.63.126.51" for MicroCloud
Use the following command on systems that you want to join the cluster:

 microcloud join

When requested enter the passphrase:

 bouquet collarbone cathedral arbitrate

Verify the fingerprint "81ca9df0cc0a" is displayed on joining systems.
Waiting to detect systems ...