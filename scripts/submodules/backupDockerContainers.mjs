#!/usr/bin/env zx

// Create the backup directory if it doesn't exist
const backupDir = '~/docker_container_backups';
await $`mkdir -p ${backupDir}`;

// List all Docker containers
const containers = await $`docker ps -q`;

// Loop through each container and back it up
for (const container of containers.stdout.split('\n').filter(Boolean)) {
    console.log(`Backing up container: ${container}`);
    await $`docker export ${container} | gzip > ${backupDir}/${container}.tar.gz`;
}

console.log('Backup completed successfully!');
