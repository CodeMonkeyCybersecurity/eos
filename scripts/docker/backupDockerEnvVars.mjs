#!/usr/bin/env zx

const backupDir = `/opt/backups/dockerBackups/EnvVars`;  // Adjust this path as needed

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
  const containers = await $`docker ps -aq`;

  // Loop through each container and back up its environment variables
  for (const container of containers.stdout.split('\n').filter(Boolean)) {
    console.log(`Backing up environment variables for container: ${container}`);
    const envVars = await $`docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' ${container}`;
    const envFile = `${backupDir}/${container}_env_vars.txt`;

    // Write environment variables to file
    await $`echo "${envVars.stdout}" > ${envFile}`;
  }

  console.log('Environment variables backup completed successfully!');
}

// Call the main function
await main();
