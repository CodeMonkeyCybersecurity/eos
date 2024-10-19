#!/usr/bin/env zx

const backupDir = `/opt/backups/dockerBackups`;  // Adjust this path as needed

// Create the backup directory if it doesn't exist
await $`mkdir -p ${backupDir}`;

// Get the list of Docker volumes
const { stdout } = await $`docker volume ls -q`;
const volumes = stdout.trim().split('\n');

// Function to create a timestamp for the backup
const timestamp = new Date().toISOString().replace(/[-:.T]/g, '').split('.')[0];

for (const volume of volumes) {
  console.log(`Backing up volume: ${volume}`);
  try {
    // Define the local backup directory for this volume
    const volumeBackupDir = `${backupDir}/${volume}_${timestamp}`;

    // Mount the Docker volume in a temporary Alpine container and copy the contents using cp
    console.log(`Creating backup for volume ${volume} at ${volumeBackupDir}`);
    await $`mkdir -p ${volumeBackupDir}`;
    await $`docker run --rm -v ${volume}:/volume -v ${volumeBackupDir}:/backup alpine sh -c "cp -r /volume/. /backup/"`;

    console.log(`Backup for volume ${volume} completed.`);
  } catch (error) {
    console.error(`Failed to back up volume: ${volume}`);
    console.error(error);
  }
}

console.log('Backup completed successfully!');
