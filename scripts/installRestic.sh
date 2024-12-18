# install restic
sudo apt-get install restic

# ssh
sudo ssh-keygen
sudo ssh-copy-id henry@backup

# initialise
sudo restic -r sftp:henry@backup:/srv/restic-repos/$(hostname) init

# backup 
sudo restic -r sftp:henry@backup:/srv/restic-repos/$(hostname) --verbose backup /root /home /var /etc /srv /usr /opt

# TODO: compression

# TODO: encryption 