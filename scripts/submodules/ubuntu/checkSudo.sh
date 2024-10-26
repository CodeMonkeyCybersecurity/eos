#!/bin/bash
# checkSudo.sh

check_sudo() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "\e[31m✘ This script must be run as root. Please use sudo.\e[0m"
    exit 1
  else
    echo -e "\e[32m✔ Running as root.\e[0m"
  fi
}

# Call the function automatically when sourced
check_sudo
