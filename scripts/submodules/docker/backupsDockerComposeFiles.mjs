#!/usr/bin/env zx

// Create the backup directory if it doesn't exist
const backupDir = '~/docker_compose_backups';
await $`mkdir -p ${backupDir}`;

// Specify the path to your Docker Compose files
const composeFiles = ['./docker-compose.yml', './docker-compose.override.yml'];

// Copy each compose file to the backup directory
for (const file of composeFiles) {
    if (await $`test -f ${file}`) {
        console.log(`Backing up Docker Compose file: ${file}`);
        await $`cp ${file} ${backupDir}/`;
    } else {
        console.log(`File does not exist: ${file}`);
    }
}

console.log('Docker Compose files backup completed successfully!');
