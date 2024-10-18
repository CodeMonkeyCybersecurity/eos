#!/usr/bin/env zx

// Create the backup directory if it doesn't exist
const backupDir = '~/docker_image_backups';
await $`mkdir -p ${backupDir}`;

// List all Docker images
const images = await $`docker images -q`;

// Loop through each image and back it up
for (const image of images.stdout.split('\n').filter(Boolean)) {
    console.log(`Backing up image: ${image}`);
    await $`docker save -o ${backupDir}/${image}.tar ${image}`;
}

console.log('Backup completed successfully!');
