#!/usr/bin/env zx

// Create the backup directory if it doesn't exist
const backupDir = '~/docker_network_backups';
await $`mkdir -p ${backupDir}`;

// List all Docker networks
const networks = await $`docker network ls -q`;

// Loop through each network and back it up
for (const network of networks.stdout.split('\n').filter(Boolean)) {
    console.log(`Backing up network: ${network}`);
    await $`docker network inspect ${network} > ${backupDir}/${network}.json`;
}

console.log('Network backup completed successfully!');
