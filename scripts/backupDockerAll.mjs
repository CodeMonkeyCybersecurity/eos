#!/usr/bin/env zx

const os = require('os');
const fs = require('fs'); // Import filesystem module
const path = require('path'); // Import path module
const homeDir = os.homedir();
import readline from 'readline';

// Define your Docker container name or ID
const DOCKER_CONTAINER_NAME = 'borgBackupDocker'; // Replace with your actual container name or ID, we use this as a default and strongly recommend not changing it because we reference it in other backup scripts. Of course, if you are sure you know what you are doing then don't let us stop you. 

const backupConfig = {
  baseDir: `${homeDir}/dockerBackups`,
  volumes: `${homeDir}/dockerBackups/Volumes`,
  containers: `${homeDir}/dockerBackups/Containers`,
  images: `${homeDir}/dockerBackups/Images`,
  networks: `${homeDir}/dockerBackups/Networks`,
  envVars: `${homeDir}/dockerBackups/EnvVars`,
  bindMounts: `${homeDir}/dockerBackups/BindMounts`,
  swarm: `${homeDir}/dockerBackups/Swarm`,
  repoDir: `${homeDir}/dockerBackups/borg_repo`,
};

const TIMESTAMP = new Date().toISOString().replace(/[-:.T]/g, '').split('.')[0]; // Format: YYYYMMDD_HHMMSS
console.log(`Processing timestamp: ${TIMESTAMP}`);

// Centralized error handling function
function handleError(error, contextMessage = '') {
  console.error(contextMessage);
  console.error(`Error: ${error.stderr || error.message}`);
}

// Function to ask user for input
function askQuestion(query) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  
  return new Promise(resolve => rl.question(query, answer => {
    rl.close();
    resolve(answer);
  }));
}

// Function to check if the Borg container exists
async function checkBorgBackupDockerContainerExistence() {
  const { stdout: containerList } = await $`docker ps -a --format "{{.Names}}"`;
  const containers = containerList.trim().split('\n');

  if (!containers.includes(DOCKER_CONTAINER_NAME)) {
    console.log(`Container "${DOCKER_CONTAINER_NAME}" does not exist. Creating it...`);
    await $`docker run -d --restart unless-stopped --name ${DOCKER_CONTAINER_NAME} alpine sh -c "while true; do sleep 30; done"`; // Create an Alpine container that runs indefinitely
  } else {
    console.log(`Container "${DOCKER_CONTAINER_NAME}" already exists.`);
  }
}

// Function to check if Borg is installed in the Docker container
async function checkBorgBackupDockerInstallationInContainer() {
  try {
    // check if Borg is installed
    await $`docker exec ${DOCKER_CONTAINER_NAME} borg --version`;
    console.log('Borg is already installed in the container.');
  } catch (error) {
    console.error('Borg is not installed in the container. Attempting to install it...');

    // Use readline to ask for user input (updated from prompt function)
    const installChoice = await askQuestion('Would you like to install Borg in the container? [y/N]: ');

    // Check user input
    if (installChoice.trim().toLowerCase() === 'y') {
      console.log('Installing Borg in the Docker container...');

      // Check if the container is Alpine-based or use appropriate installation method
      await $`docker exec ${DOCKER_CONTAINER_NAME} sh -c "apk add --no-cache borgbackup"`; // For Alpine containers
      // For Ubuntu/Debian-based containers, use the following instead:
      // await $`docker exec ${DOCKER_CONTAINER_NAME} sh -c "apt update && apt install -y borgbackup"`;
    } else {
      console.error('Borg is required for this backup script. Exiting...');
      process.exit(1); // Exit the script if the user chooses not to install
    }
  }
}

// Function to create all backup directories
async function createBackupDirectories() {
  const dirsToCreate = Object.values(backupConfig);
  await Promise.all(dirsToCreate.map(dir => $`mkdir -p ${dir}`));
}

// Function to initialize Borg repository
async function initializeBorgRepo() {
  const repoExists = await $`borg list ${backupConfig.repoDir} || true`;
  if (!repoExists.stdout) {
    await $`borg init --encryption=repokey ${backupConfig.repoDir}`;
  }
}

// Function to back up Docker volumes
async function backupVolumes() {
  const { stdout: volumesStdout } = await $`docker volume ls -q`;
  const volumes = volumesStdout.trim().split('\n').filter(volume => volume);

  for (const volume of volumes) {
    console.log(`Backing up volume: ${volume}`);
    try {
      // Mount the volume inside the borgBackupDocker container and run Borg from there
      await $`docker exec -it ${DOCKER_CONTAINER_NAME} sh -c "borg create --stats --progress ${backupConfig.repoDir}::${volume}_${TIMESTAMP} /var/lib/docker/volumes/${volume}/_data"`;
    } catch (error) {
      console.error(`Failed to back up volume: ${volume}`);
      handleError(error);
    }
  }
}

// Function to back up bind mounts
async function backupBindMounts() {
  const { stdout: containersStdout } = await $`docker ps -q`;
  const containerIds = containersStdout.trim().split('\n').filter(id => id);

  const bindMounts = new Set();
  for (const containerId of containerIds) {
    const { stdout: mountsStdout } = await $`docker inspect ${containerId} --format='{{json .Mounts}}'`;
    const mounts = JSON.parse(mountsStdout);
    for (const mount of mounts) {
      if (mount.Type === 'bind') {
        bindMounts.add(mount.Source);
      }
    }
  }

  for (const bindMount of bindMounts) {
    const bindMountName = bindMount.replace(/[\/\\]/g, '_'); // Replace slashes for a valid filename
    console.log(`Backing up bind mount: ${bindMount}`);
    try {
      // Use borgBackupDocker to back up the bind mount
      await $`docker exec -v ${bindMount}:/bind ${DOCKER_CONTAINER_NAME} borg create --stats --progress ${backupConfig.repoDir}::${bindMountName}_${TIMESTAMP} /bind`;
    } catch (error) {
      console.error(`Failed to back up bind mount: ${bindMount}`);
      handleError(error);
    }
  }
}

  for (const bindMount of bindMounts) {
    console.log(`Processing bindMount: ${bindMount}`);
    const bindMountName = bindMount.replace(/[\/\\]/g, '_'); // Replace forward and backward slashes with an underscore
    console.log(`Backing up bind mount: ${bindMount}`);
    try {
      await $`borg create --stats --progress ${backupConfig.repoDir}::${bindMountName}_${TIMESTAMP} ${bindMount}`;
    } catch (error) {
      console.error(`Failed to back up bind mount: ${bindMount}`);
      console.error(`Error: ${error.stderr || error.message}`);
    }
  }
}

// Function to back up Docker containers
async function backupContainers() {
  const { stdout: containersStdout } = await $`docker ps -q`;
  const containerIds = containersStdout.trim().split('\n').filter(id => id);

  for (const containerId of containerIds) {
    const { stdout: containerName } = await $`docker inspect --format='{{.Name}}' ${containerId}`;
    const sanitizedContainerName = containerName.replace(/^\//, ''); // Remove leading slash

    console.log(`Backing up container: ${sanitizedContainerName}`);
    try {
      // Use borgBackupDocker to handle container exports and compress them using Borg
      await $`docker export ${containerId} | docker exec -i ${DOCKER_CONTAINER_NAME} borg create --stats --progress ${backupConfig.repoDir}::${sanitizedContainerName}_${TIMESTAMP} -`;
    } catch (error) {
      console.error(`Failed to back up container: ${sanitizedContainerName}`);
      handleError(error);
    }
  }
}

// Function to back up Docker images
async function backupImages() {
  const { stdout: imagesStdout } = await $`docker images --format "{{.Repository}}:{{.Tag}}"`;
  const images = imagesStdout.trim().split('\n').filter(image => image);

  for (const image of images) {
    const sanitizedImageName = image.replace(/[\/:]/g, '_'); // Replace slashes and colons for a valid filename
    console.log(`Backing up image: ${image}`);
    try {
      // Use borgBackupDocker to handle image exports and compress them using Borg
      await $`docker save ${image} | docker exec -i ${DOCKER_CONTAINER_NAME} borg create --stats --progress ${backupConfig.repoDir}::${sanitizedImageName}_${TIMESTAMP} -`;
    } catch (error) {
      console.error(`Failed to back up image: ${image}`);
      handleError(error);
    }
  }
}

// Function to back up Docker networks
async function backupNetworks() {
  const { stdout: networksStdout } = await $`docker network ls -q`;
  const networkIds = networksStdout.trim().split('\n').filter(id => id);

  for (const networkId of networkIds) {
    const { stdout: networkName } = await $`docker network inspect ${networkId} --format '{{.Name}}'`;
    const sanitizedNetworkName = networkName.replace(/[\/:]/g, '_'); // Replace slashes and colons for a valid filename

    console.log(`Backing up network: ${networkName}`);
    try {
      // Use borgBackupDocker to save the network configuration inside the backup repository
      await $`docker network inspect ${networkId} | docker exec -i ${DOCKER_CONTAINER_NAME} borg create --stats --progress ${backupConfig.repoDir}::${sanitizedNetworkName}_${TIMESTAMP} -`;
    } catch (error) {
      console.error(`Failed to back up network: ${networkName}`);
      handleError(error);
    }
  }
}

// Function to back up environment variables from Docker containers
async function backupEnvVars() {
  const { stdout: containersStdout } = await $`docker ps -q`;
  const containerIds = containersStdout.trim().split('\n').filter(id => id);

  for (const containerId of containerIds) {
    const { stdout: containerName } = await $`docker inspect --format='{{.Name}}' ${containerId}`;
    const sanitizedContainerName = containerName.replace(/^\//, ''); // Remove leading slash

    console.log(`Backing up environment variables for container: ${sanitizedContainerName}`);
    try {
      const { stdout: envVars } = await $`docker inspect --format='{{range .Config.Env}}{{.}} {{end}}' ${containerId}`;
      const envVarsArray = envVars.split(' ').filter(Boolean); // Split and filter empty values

      // Save environment variables inside borgBackupDocker
      await $`echo ${JSON.stringify(envVarsArray, null, 2)} | docker exec -i ${DOCKER_CONTAINER_NAME} borg create --stats --progress ${backupConfig.repoDir}::${sanitizedContainerName}_env_vars_${TIMESTAMP} -`;
    } catch (error) {
      console.error(`Failed to back up environment variables for container: ${sanitizedContainerName}`);
      handleError(error);
    }
  }
}

// Cleanup function to remove old backups
async function cleanupOldBackups() {
  const daysToKeep = 30; // Number of days to keep backups
  console.log(`Cleaning up old backups... Keeping backups for the last ${daysToKeep} days.`);

  try {
    // Use borg prune to automatically clean up old backups inside the borgBackupDocker container
    await $`docker exec ${DOCKER_CONTAINER_NAME} borg prune --keep-daily=${daysToKeep} --keep-weekly=4 --keep-monthly=6 ${backupConfig.repoDir}`;
    
    console.log('Cleanup completed successfully.');
  } catch (error) {
    console.error('Failed to clean up old backups.');
    handleError(error);
  }
}

// Main script execution
(async () => {
  await checkBorgBackupDockerContainerExistence(); // Check if the Borg container exists, creates it if not
  await checkBorgBackupDockerInstallationInContainer(); // Check if Borg is installed in the Docker container
  await createBackupDirectories(); // Create all backup directories
  await initializeBorgRepo(); // Initialize the Borg repository
  await backupVolumes(); // Back up Docker volumes
  await backupBindMounts(); // Back up bind mounts
  await backupContainers(); // Back up containers
  await backupImages(); // Back up images
  await backupNetworks(); // Back up networks
  await backupEnvVars(); // Back up EnvVars
  await cleanupOldBackups(); // Cleanup old backups

  console.log('Backup completed successfully!');
})();
