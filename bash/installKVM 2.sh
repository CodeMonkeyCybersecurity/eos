#!/bin/bash
# https://help.ubuntu.com/community/KVM/Installation

egrep -c '(vmx|svm)' /proc/cpuinfo
cat /sys/hypervisor/properties/capabilities
kvm-ok 

egrep -c ' lm ' /proc/cpuinfo
uname -m

sudo apt-get install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils

sudo adduser `id -un` libvirt
sudo adduser `id -un` kvm

virsh list --all

sudo chown root:libvirtd /dev/kvm

sudo apt-get install virt-manager
