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
    
  await $`mkdir -p ${backupDir}/docker_swarm_backups`;

  // List all Docker services in the swarm
  const services = await $`docker service ls -q`;

  // Loop through each service and back it up
  for (const service of services.stdout.split('\n').filter(Boolean)) {
    console.log(`Backing up service: ${service}`);
    await $`docker service inspect ${service} > ${backupDir}/docker_swarm_backups/${service}.json`;
  }

  // List all Docker configs
  const configs = await $`docker config ls -q`;

  // Loop through each config and back it up
  for (const config of configs.stdout.split('\n').filter(Boolean)) {
    console.log(`Backing up config: ${config}`);
    await $`docker config inspect ${config} > ${backupDir}/docker_swarm_backups/${config}.json`;
  }

  // List all Docker secrets
  const secrets = await $`docker secret ls -q`;

  // Loop through each secret and back it up
  for (const secret of secrets.stdout.split('\n').filter(Boolean)) {
    console.log(`Backing up secret: ${secret}`);
    await $`docker secret inspect ${secret} > ${backupDir}/docker_swarm_backups/${secret}.json`;
  }

  console.log('Swarm backup completed successfully!');
}

// Call the main function
await main();
