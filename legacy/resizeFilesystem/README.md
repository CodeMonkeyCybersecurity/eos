# Expanding an `ubuntu--vg-ubuntu--lv` logical volume
To expand the `ubuntu--vg-ubuntu--lv` logical volume to use the full xxxGB of space available on the volume group, follow these steps:

## 1. Check the current size of the logical volume (LV):
```
df -h /
sudo lvdisplay
```

This will confirm the current size of the logical volume and ensure it’s the one you want to resize.

## 2. Check the available space in the volume group (VG):
```
sudo vgdisplay ubuntu-vg
```
Look for the Free PE (Physical Extents) field to see how much unallocated space is available in the volume group. You should see enough free space to expand the logical volume to the full 126GB.

## 3. Expand the logical volume:
Resize it to fill all available space in the volume group:
```
sudo lvresize -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
```

## 4. Resize the filesystem:
After resizing the logical volume, resize the filesystem to make use of the new space. Assuming you’re using an ext4 filesystem (which is typical for Linux root partitions):
```
sudo resize2fs /dev/ubuntu-vg/ubuntu-lv
```
## 5. Verify the changes:

Check that the logical volume and filesystem have been resized successfully:
```
df -h /
sudo lvdisplay
```

Notes:
* Replace /dev/ubuntu-vg/ubuntu-lv with the correct logical volume path if it differs in your setup.
* The above commands do not require unmounting the filesystem, as you’re resizing the root filesystem while it’s in use.

