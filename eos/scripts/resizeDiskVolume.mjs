#!/usr/bin/env zx

import { $ } from 'zx';
import inquirer from 'inquirer';
import drivelist from 'drivelist';

// List available disks and partitions
async function listDisks() {
  const drives = await drivelist.list();
  drives.forEach((drive) => {
    console.log(`Device: ${drive.device}`);
    console.log(`Description: ${drive.description}`);
    console.log(`Size: ${drive.size}`);
    console.log(`Mountpoints: ${JSON.stringify(drive.mountpoints, null, 2)}`);
    console.log('---');
  });
}

// Resize the partition using parted
async function resizePartition(disk, partition, newSize) {
  try {
    console.log(`Resizing partition ${partition} on ${disk} to ${newSize}...`);
    await $`sudo parted ${disk} resizepart ${partition} ${newSize}`;
    console.log(`Partition ${partition} resized to ${newSize}`);
  } catch (error) {
    console.error(`Error resizing partition: ${error.message}`);
  }
}

// Resize the filesystem using resize2fs
async function resizeFilesystem(partition) {
  try {
    console.log(`Resizing filesystem on ${partition}...`);
    await $`sudo resize2fs ${partition}`;
    console.log(`Filesystem on ${partition} resized successfully.`);
  } catch (error) {
    console.error(`Error resizing filesystem: ${error.message}`);
  }
}

// Get user input and perform resize
async function getUserInput() {
  await listDisks();

  const answers = await inquirer.prompt([
    {
      type: 'input',
      name: 'disk',
      message: 'Enter the disk to manage (e.g., /dev/sda):',
    },
    {
      type: 'input',
      name: 'partition',
      message: 'Enter the partition number to resize (e.g., 1):',
    },
    {
      type: 'input',
      name: 'newSize',
      message: 'Enter the new size (e.g., 20G for 20 GB):',
    },
  ]);

  const partitionPath = `${answers.disk}${answers.partition}`;
  await resizePartition(answers.disk, answers.partition, answers.newSize);
  await resizeFilesystem(partitionPath);
}

getUserInput();
