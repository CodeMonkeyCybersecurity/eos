#!/usr/bin/env zx

// Backup directory for Docker Compose files
const backupDir = `/opt/backups/dockerBackups/docker_compose_backups`;

// Function to check if the script is run with sudo/root
function checkRootUser() {
  if (process.getuid && process.getuid() !== 0) {
    console.error("This script must be run with sudo or as root.");
    process.exit(1); // Exit if not run as root
  }
}

// Main function to run the script logic
async function main() {
  // Check if the script is run as root
  checkRootUser();

  try {
    // Create the backup directory if it doesn't exist
    await $`mkdir -p ${backupDir}`;

    // Search for Docker Compose files recursively under /home and /root
    console.log('Searching for Docker Compose files under /home and /root');
    const { stdout: composeFiles } = await $`find /home /root -name 'docker-compose.yml'`;

    // Copy each found compose file to the backup directory
    for (const file of composeFiles.split('\n').filter(Boolean)) {
      console.log(`Backing up Docker Compose file: ${file}`);
      await $`cp ${file} ${backupDir}/`;
    }

    console.log('Docker Compose file backup completed successfully!');
  } catch (error) {
    console.error(`Error during backup: ${error.message}`);
  }
}

// Call the main function
await main();
