#1/bin/bash
# debuggingPATH.sh

# Checking the PATH Environment Variable
echo $PATH
bash --login -c 'echo $PATH'

# Inspecting Files that Modify PATH
grep -i path ~/.bashrc ~/.profile ~/.bash_aliases /etc/profile /etc/bash.bashrc /etc/environment /etc/profile.d/*

# Checking Snap Setup
sudo systemctl status snapd

# Ensuring No Duplicate Entries
cat /etc/environment
cat ~/.bashrc
cat ~/.profile
cat /etc/profile.d/apps-bin-path.sh

#Testing Changes Without Rebooting
source /etc/profile
source ~/.bashrc
bash --login -c 'echo $PATH'

# reboot testing
sudo reboot