#!/usr/bin/env zx

// Import the zx module
import 'zx';

// Function to check if the script is run with sudo privileges
async function checkSudo() {
  if (os.userInfo().uid !== 0) {
    console.error('This script must be run with sudo privileges!');
    process.exit(1);
  }
}

// Function to install ZFS on Ubuntu
async function installZFS() {
  try {
    await $`apt update`;
    await $`apt install -y zfsutils-linux`;
    console.log('ZFS installed successfully.');
  } catch (error) {
    console.error('Failed to install ZFS:', error);
    process.exit(1);
  }
}

// Function to create a ZFS pool
async function createZFSPool(poolName, disks) {
  try {
    const diskList = disks.join(' ');
    await $`zpool create ${poolName} ${diskList}`;
    console.log(`ZFS pool '${poolName}' created with disks: ${disks.join(', ')}`);
  } catch (error) {
    console.error('Failed to create ZFS pool:', error);
    process.exit(1);
  }
}

// Main function to orchestrate ZFS deployment
async function main() {
  await checkSudo();

  console.log('Installing ZFS...');
  await installZFS();

  const poolName = await question('Enter the name for the ZFS pool: ');
  const disksInput = await question('Enter the disk devices for the ZFS pool (space-separated, e.g., /dev/sdb /dev/sdc): ');
  const disks = disksInput.split(' ');

  console.log(`Creating ZFS pool '${poolName}' with disks: ${disks.join(', ')}`);
  await createZFSPool(poolName, disks);

  console.log('ZFS deployment completed successfully.');
}

await main();
