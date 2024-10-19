#!/usr/bin/env zx

const os = require('os');
const backupDir = `/opt/backups/dockerBackups/docker_compose_backups`;  // Adjust this path as needed
const baseDir = `${os.homedir()}`;  // Your home directory

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

  await $`mkdir -p ${backupDir}`;  // Create the backup directory

  // Automatically find all docker-compose.yml files in the home directory
  const { stdout: composeFiles } = await $`find ${baseDir} -name 'docker-compose.yml'`;

  // Copy each found compose file to the backup directory
  for (const file of composeFiles.split('\n').filter(Boolean)) {
    console.log(`Backing up Docker Compose file: ${file}`);
    await $`cp ${file} ${backupDir}/`;
  }

  console.log('Docker Compose file backup completed successfully!');
}

// Call the main function
await main();
