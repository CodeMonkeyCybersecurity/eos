#!/usr/bin/env zx

// Create the backup directory if it doesn't exist
const backupDir = '~/docker_volume_backups';
await $`mkdir -p ${backupDir}`;

// List all Docker volumes
const volumes = await $`docker volume ls -q`;

// Loop through each volume and back it up
for (const volume of volumes.stdout.split('\n').filter(Boolean)) {
    console.log(`Backing up volume: ${volume}`);
    await $`docker run --rm -v ${volume}:/volume -v ${backupDir}:/backup alpine sh -c "cd /volume && tar czf /backup/${volume}.tar.gz ."`;
}

console.log('Backup completed successfully!');
