sudo vgdisplay

sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv

sudo resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv

df -h

lsblk
sudo lvdisplay