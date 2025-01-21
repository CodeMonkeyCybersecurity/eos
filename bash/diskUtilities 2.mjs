#!/usr/bin/env zx

// Importing zx modules
import { $, question } from 'zx';

// Function to list all disks
async function listDisks() {
  await $`lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT`;
}

// Function to check disk usage
async function checkDiskUsage() {
  await $`df -h`;
}

// Function to mount a disk
async function mountDisk() {
  const disk = await question('Enter the disk to mount (e.g., /dev/sdb1): ');
  const mountPoint = await question('Enter the mount point (e.g., /mnt/mydisk): ');
  await $`sudo mount ${disk} ${mountPoint}`;
  console.log(`Disk ${disk} mounted at ${mountPoint}`);
}

// Function to unmount a disk
async function unmountDisk() {
  const mountPoint = await question('Enter the mount point to unmount (e.g., /mnt/mydisk): ');
  await $`sudo umount ${mountPoint}`;
  console.log(`Unmounted disk at ${mountPoint}`);
}

// Function to check and repair filesystem
async function checkRepairFilesystem() {
  const disk = await question('Enter the disk to check (e.g., /dev/sdb1): ');
  await $`sudo fsck ${disk}`;
  console.log(`Filesystem check and repair done for ${disk}`);
}

// Function to create a partition
async function createPartition() {
  const disk = await question('Enter the disk to partition (e.g., /dev/sdb): ');
  console.log('Starting parted for partitioning...');
  await $`sudo parted ${disk}`;
}

// Function to format a partition
async function formatPartition() {
  const partition = await question('Enter the partition to format (e.g., /dev/sdb1): ');
  const fsType = await question('Enter the filesystem type (e.g., ext4, ntfs): ');
  await $`sudo mkfs.${fsType} ${partition}`;
  console.log(`Partition ${partition} formatted as ${fsType}`);
}

// Function to resize a partition
async function resizePartition() {
  const disk = await question('Enter the disk to resize a partition on (e.g., /dev/sdb): ');
  const partitionNumber = await question('Enter the partition number to resize (e.g., 1 for /dev/sdb1): ');
  const newSize = await question('Enter the new size for the partition (e.g., 20G, 50%): ');
  
  console.log(`Resizing partition ${disk}${partitionNumber} to ${newSize}...`);
  await $`sudo parted ${disk} resizepart ${partitionNumber} ${newSize}`;
  console.log(`Partition ${disk}${partitionNumber} resized to ${newSize}`);
}

// Main function to provide a menu for disk utility tasks
async function main() {
  console.log('Disk Utility Tasks:');
  console.log('1. List all disks');
  console.log('2. Check disk usage');
  console.log('3. Mount a disk');
  console.log('4. Unmount a disk');
  console.log('5. Check and repair filesystem');
  console.log('6. Create a partition');
  console.log('7. Format a partition');
  console.log('8. Resize a partition');
  
  const choice = await question('Enter the number of the task you want to perform: ');

  switch (choice) {
    case '1':
      await listDisks();
      break;
    case '2':
      await checkDiskUsage();
      break;
    case '3':
      await mountDisk();
      break;
    case '4':
      await unmountDisk();
      break;
    case '5':
      await checkRepairFilesystem();
      break;
    case '6':
      await createPartition();
      break;
    case '7':
      await formatPartition();
      break;
    case '8':
      await resizePartition();
      break;
    default:
      console.log('Invalid choice. Exiting.');
  }
}

// Run the main function
await main();
