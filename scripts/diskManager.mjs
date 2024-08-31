#!/usr/bin/env zx

import { $ } from 'zx';
import drivelist from 'drivelist';
import inquirer from 'inquirer';

// List available disks
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

// Create a new partition
async function createPartition(disk) {
  try {
    await $`sudo fdisk ${disk} <<< $'n\np\n1\n\n\nw'`;
    console.log(`Partition created on ${disk}`);
  } catch (error) {
    console.error(`Error creating partition: ${error.message}`);
  }
}

// Format a partition as ext4
async function formatPartition(partition) {
  try {
    await $`sudo mkfs.ext4 ${partition}`;
    console.log(`Partition formatted as ext4: ${partition}`);
  } catch (error) {
    console.error(`Error formatting partition: ${error.message}`);
  }
}

// Mount a partition
async function mountPartition(partition, mountPoint) {
  try {
    await $`sudo mount ${partition} ${mountPoint}`;
    console.log(`Partition mounted at ${mountPoint}`);
  } catch (error) {
    console.error(`Error mounting partition: ${error.message}`);
  }
}

// Get user input and perform actions
async function getUserInput() {
  await listDisks();

  const answers = await inquirer.prompt([
    {
      type: 'input',
      name: 'disk',
      message: 'Enter the disk you want to partition (e.g., /dev/sdb):',
    },
    {
      type: 'input',
      name: 'mountPoint',
      message: 'Enter the mount point for the partition (e.g., /mnt/data):',
    },
  ]);

  await createPartition(answers.disk);
  await formatPartition(`${answers.disk}1`);
  await mountPartition(`${answers.disk}1`, answers.mountPoint);
}

getUserInput();
