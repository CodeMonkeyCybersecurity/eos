#!/usr/bin/env zx

const backupDir = `/opt/backups/dockerBackups/docker_swarm_backups`;  // Adjust this path as needed

// Function to check if the script is run with sudo/root
function checkRootUser() {
  if (process.getuid && process.getuid() !== 0) {
    console.error("This script must be run with sudo or as root.");
    process.exit(1); // Exit if not run as root
  }
}

// Function to check if the node is part of a Docker Swarm
async function isSwarmManager() {
  try {
    // Check Docker Swarm status
    const { stdout } = await $`docker info --format '{{.Swarm.LocalNodeState}}'`;
    return stdout.trim() === 'active';  // 'active' means the node is a Swarm manager
  } catch (error) {
    console.error('Error checking Docker Swarm status:', error.message);
    return false;
  }
}

// Main function to run the script logic
async function main() {
  // Check if the script is run as root
  checkRootUser();

  // Check if the node is a Swarm manager
  if (!(await isSwarmManager())) {
    console.log("This node is not a Swarm manager. Skipping Docker Swarm backup.");
    process.exit(0); // Exit gracefully without throwing an error
  }

  await $`mkdir -p ${backupDir}`;

  // List all Docker services in the Swarm
  const services = await $`docker service ls -q`;

  // Loop through each service and back it up
  for (const service of services.stdout.split('\n').filter(Boolean)) {
    console.log(`Backing up service: ${service}`);
    await $`docker service inspect ${service} > ${backupDir}/${service}.json`;
  }

  // List all Docker configs
  const configs = await $`docker config ls -q`;

  // Loop through each config and back it up
  for (const config of configs.stdout.split('\n').filter(Boolean)) {
    console.log(`Backing up config: ${config}`);
    await $`docker config inspect ${config} > ${backupDir}/${config}.json`;
  }

  // List all Docker secrets
  const secrets = await $`docker secret ls -q`;

  // Loop through each secret and back it up
  for (const secret of secrets.stdout.split('\n').filter(Boolean)) {
    console.log(`Backing up secret: ${secret}`);
    await $`docker secret inspect ${secret} > ${backupDir}/${secret}.json`;
  }

  console.log('Docker Swarm backup completed successfully!');
}

// Call the main function
await main();
