#!/usr/bin/env zx

const backupDir = `/opt/backups/dockerBackups/docker_dockerfiles_backups`;  // Adjust this path as needed

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

    // Automatically find all Dockerfiles under /home and /root
    console.log('Searching for Dockerfiles under /home and /root');
    const { stdout: dockerFiles } = await $`find /home /root -name 'Dockerfile'`;

    for (const file of dockerFiles.split('\n').filter(Boolean)) {
      console.log(`Backing up Dockerfile: ${file}`);
      await $`cp ${file} ${backupDir}/`;
    }

    // Optionally back up the context (files in the same directory as the Dockerfile)
    console.log('Backing up Dockerfile build contexts');
    const { stdout: dirs } = await $`find /home /root -name '.'`;
    for (const dir of dirs.split('\n').filter(Boolean)) {
      console.log(`Backing up build context for: ${dir}`);
      await $`cp -r ${dir}/* ${backupDir}/`;
    }

    console.log('Dockerfile and build context backup completed successfully!');
  } catch (error) {
    console.error(`Error during backup: ${error.message}`);
  }
}

// Call the main function
await main();
