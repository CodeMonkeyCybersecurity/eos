#!/usr/bin/env zx

const backupDir = `/opt/backups/dockerBackups`;  // Adjust this path as needed

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

  // Create the backup directory if it doesn't exist
  await $`mkdir -p ${backupDir}`;

  // List all Docker containers
  const containers = await $`docker ps -q`;

  // Loop through each container and back it up
  for (const container of containers.stdout.split('\n').filter(Boolean)) {
    console.log(`Backing up container: ${container}`);
    await $`docker export ${container} > ${backupDir}/${container}`;
  }

  console.log('Backup completed successfully!');
}

// Call the main function
await main();
