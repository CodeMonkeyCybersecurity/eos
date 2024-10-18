#!/usr/bin/env zx

import { $, cd } from 'zx';
import os from 'os';

const homeDir = os.homedir();
const backupDir = `${homeDir}/docker_volume_backups`;

// Create the backup directory if it doesn't exist
await $`mkdir -p ${backupDir}`;

// Get list of all containers
const { stdout: containersStdout } = await $`docker ps -q`;
const containerIds = containersStdout.trim().split('\n').filter(id => id);

const bindMounts = new Set();

for (const containerId of containerIds) {
  const { stdout: mountsStdout } = await $`docker inspect ${containerId} --format='{{json .Mounts}}'`;
  const mounts = JSON.parse(mountsStdout);

  for (const mount of mounts) {
    if (mount.Type === 'bind') {
      bindMounts.add(mount.Source);
    }
  }
}

// Back up Docker volumes as before
const { stdout } = await $`docker volume ls -q`;
const volumes = stdout.trim().split('\n').filter(volume => volume);

for (const volume of volumes) {
  console.log(`Backing up volume: ${volume}`);
  try {
    await $`docker run --rm -v ${volume}:/volume -v ${backupDir}:/backup alpine sh -c "cd /volume && tar czf /backup/${volume}.tar.gz ."`
  } catch (error) {
    console.error(`Failed to back up volume: ${volume}`);
    console.error(error);
  }
}

// Back up bind mounts
for (const bindMount of bindMounts) {
  const bindMountName = bindMount.replace(/[\/\\]/g, '_'); // Replace slashes for a valid filename
  console.log(`Backing up bind mount: ${bindMount}`);
  try {
    await $`sudo tar czf ${backupDir}/bind_${bindMountName}.tar.gz -C ${bindMount} .`;
  } catch (error) {
    console.error(`Failed to back up bind mount: ${bindMount}`);
    console.error(error);
  }
}

console.log('Backup completed successfully!');
