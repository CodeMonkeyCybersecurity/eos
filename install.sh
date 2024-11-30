!#/bin/bash

check_sudo() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "\e[31m✘ This script must be run as root. Please use sudo.\e[0m"
    exit 1
  else
    echo -e "Running as root."
  fi
}

mkdir -p /usr/local/bin/eos 
chmod +x /usr/local/bin/eos
mv ~/Eos /usr/local/bin/eos
sudo chmod +x /usr/local/bin/eos/scripts/*.sh

echo "Finis"
