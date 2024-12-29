# install restic
sudo apt-get install restic

# ssh
sudo ssh-keygen
sudo ssh-copy-id henry@backup

# initialise
sudo restic -r sftp:henry@backup:/srv/restic-repos/$(hostname) init

# backup 
sudo restic -r sftp:henry@backup:/srv/restic-repos/$(hostname) --verbose backup /root /home /var /etc /srv /usr /opt

read -p "What is your restic repo password?: " RESTIC_PASS

echo "$RESTIC_PASS" | sudo tee /root/.restic-password > /dev/null
sudo chmod 600 /root/.restic-password
RESTIC_REPO="sftp:henry@backup:/srv/restic-repos/$(hostname)"
echo "$RESTIC_REPO" | sudo tee /root/.restic-repo > /dev/null
sudo chmod 600 /root/.restic-repo

sudo restic --repository-file /root/.restic-repo --password-file /root/.restic-password --verbose backup /root /home /var /etc /srv /usr /opt

