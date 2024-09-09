#!/bin/bash

# Function to generate the output file name and create the file
output_file () {
    # Generate the current date, time, and machine name
    timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
    machine_name=$(hostname)
    user=$(whoami)
    
    # Construct the output file name
    output_file="${timestamp}_${user}_${machine_name}_ubuntuconfigs.md"
    
    # Ensure the directory exists
    sudo mkdir -p /etc/eos
    
    # Create the output file (touch to ensure it exists)
    sudo touch "/etc/eos/${output_file}"
    
    # Return the path of the output file
    echo "/etc/eos/${output_file}"
}

# Function to gather Ubuntu configurations and write them to the output file
ubuntu_configs () {
    # Capture output file path
    output_file_path="$1"
    
    # Gather system information and write it to the output file
    {
        echo "==hardware=="
        sudo lshw -short
        sudo lspci -k
        sudo lsmod
        echo "usb list: $(lsusb)"
        sudo lsblk
        sudo df -h
        sudo dmidecode
        
        echo "==drivers and firmware=="
        echo "ubuntu drivers: " && sudo ubuntu-drivers list
        echo "kernel drivers: " && sudo dmesg | grep -i driver
        echo "firmware: " && sudo dpkg -l | grep firmware
        sudo ls /lib/firmware/
        
        echo "==installed packages=="
        sudo apt list --installed
        sudo snap list
        
        echo "==crontab=="
        sudo cat /etc/crontab
        
        echo "==networking=="
        sudo ip addr
        ss -tuln
        
        echo "==services=="
        sudo service --status-all
        sudo ps aux
        sudo systemctl list-units --type=service
        
        echo "==passwords and users=="
        getent passwd
        getent group
        sudo cat /etc/sudoers | grep -v '^#' | grep -v '^$'
        echo "current users: $(users)"
    } | sudo tee -a "$output_file_path" &>> "/var/log/ubuntuconfigs.logs"
}

# Generate output file and store path
output_file_path=$(output_file)

# Run Ubuntu configurations and log output
ubuntu_configs "$output_file_path"

echo "Finished writing configurations to $output_file_path"
