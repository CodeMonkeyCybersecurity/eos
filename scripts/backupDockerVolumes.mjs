#!/usr/bin/env zx

import { $ } from 'zx';
import os from 'os';

const homeDir = os.homedir();
const backupDir = `${homeDir}/docker_volume_backups`;

// Create the backup directory if it doesn't exist
await $`mkdir -p ${backupDir}`;

// Get the list of Docker volumes
const { stdout } = await $`docker volume ls -q`;
const volumes = stdout.trim().split('\n');

for (const volume of volumes) {
  console.log(`Backing up volume: ${volume}`);
  try {
    await $`docker run --rm -v ${volume}:/volume -v ${backupDir}:/backup alpine sh -c "cd /volume && tar czf /backup/${volume}.tar.gz ."`
  } catch (error) {
    console.error(`Failed to back up volume: ${volume}`);
    console.error(error);
  }
}
console.log('Backup completed successfully!');
