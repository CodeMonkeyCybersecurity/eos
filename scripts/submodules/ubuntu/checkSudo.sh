#!/bin/bash

check_sudo() {
  if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
  fi
}
