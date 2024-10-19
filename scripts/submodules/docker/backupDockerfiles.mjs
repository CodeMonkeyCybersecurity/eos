#!/usr/bin/env zx

const os = require('os');
const backupDir = `/opt/backups/dockerBackups/docker_dockerfiles_backups`;  // Adjust this path as needed
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

  await $`mkdir -p ${backupDir}/docker_dockerfiles_backups`;

  // Automatically find all directories under the home directory containing Dockerfiles
  const dockerFiles = await $`find ${baseDir} -name 'Dockerfile'`;
  const dirs = await $`find ${baseDir} -name '.'`;

  for (const file of dockerFiles.stdout.split('\n').filter(Boolean)) {
    console.log(`Backing up Dockerfile: ${file}`);
    await $`cp ${file} ${backupDir}/`;
  }

  // Optionally back up the context (e.g., all files in the directory containing the Dockerfile)
  for (const dir of dirs.stdout.split('\n').filter(Boolean)) {
    console.log(`Backing up build context for: ${dir}`);
    await $`cp -r ${dir}/* ${backupDir}/`;
  }

  console.log('Dockerfile and build context backup completed successfully!');
}

// Call the main function
await main();
