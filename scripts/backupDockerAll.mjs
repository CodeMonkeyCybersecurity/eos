#!/usr/bin/env zx

const os = require('os');
const fs = require('fs'); // Import filesystem module
const path = require('path');
const readline = require('readline'); // Use require instead of import

// Function to check if the script is run with sudo/root
async function checkRootUser() {
  if (process.getuid && process.getuid() !== 0) {
    console.error("This script must be run with sudo or as root.");
    process.exit(1); // Exit if not run as root
  }
}

// Define your Docker container name or ID
const DOCKER_CONTAINER_NAME = 'borgbackupdocker'; // Default container name
const USER = process.env.USER; // Get the current user
const baseDir = '/opt/backups/dockerBackups'; // Define baseDir correctly as a string
const repoDir = `${baseDir}/borg_repo`; // Inside the Docker container, repo is mounted here

// Function to create timestamp
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

// Function to set your  passphrase
async function setPassphrase() {
  const passphrase = await askQuestion('Enter  passphrase: ');
  process.env.BORG_PASSPHRASE = passphrase; // Set it in the environment for the script duration
}

// Function to create the backup directory
async function createBackupDirectory() {
  try {
    console.log(`Creating backup directory at ${backupConfig.baseDir}...`);
    await $`sudo mkdir -p ${backupConfig.baseDir}`;
    console.log('Backup directory created successfully.');
  } catch (error) {
    console.error('Failed to create backup directory.');
    handleError(error);
  }
}

// Function to ensure correct permissions on the backup directory
async function ensurePermissions() {
  try {
    console.log('Ensuring permissions on backup directory...');
    await $`sudo chown -R ${USER}:${USER} ${baseDir}/borg_repo`;
    await $`sudo chmod -R 775 ${baseDir}/borg_repo`;
    console.log('Permissions set successfully.');
  } catch (error) {
    console.error('Failed to set permissions.');
    handleError(error);
  }
}

// Function to check if the Borg container exists and create it if not
async function checkContainerExistence() {
  const { stdout: containerList } = await $`docker ps -a --format "{{.Names}}"`;
  const containers = containerList.trim() ? containerList.trim().split('\n') : [];

  if (!containers.includes(DOCKER_CONTAINER_NAME)) {
    console.log(`Container "${DOCKER_CONTAINER_NAME}" does not exist. Creating it...`);

    try {
      await $`docker run -d --restart unless-stopped --name ${DOCKER_CONTAINER_NAME} \
        -v ${backupConfig.baseDir}/borg_repo:/borg_repo:rw \
        -e BORG_PASSPHRASE=${process.env.BORG_PASSPHRASE} \
        alpine sh -c "while true; do sleep 30; done"`;
      console.log(`Container "${DOCKER_CONTAINER_NAME}" created successfully.`);

      // Ensure the container is running correctly
      const { stdout: runningContainers } = await $`docker ps --format "{{.Names}}"`;
      if (!runningContainers.trim().split('\n').includes(DOCKER_CONTAINER_NAME)) {
        console.error(`Failed to start container "${DOCKER_CONTAINER_NAME}" correctly.`);
        process.exit(1); // Exit the process if it failed
      }
    } catch (error) {
      console.error(`Failed to create container "${DOCKER_CONTAINER_NAME}".`);
      handleError(error);
    }
  } else {
    console.log(`Container "${DOCKER_CONTAINER_NAME}" already exists.`);
  }
}

// Function to check if Borg is installed in the Docker container
async function checkBorgBackupDockerInstallationInContainer() {
  try {
    await $`docker exec -e BORG_PASSPHRASE=${process.env.BORG_PASSPHRASE} ${DOCKER_CONTAINER_NAME} borg --version`;
    console.log('Borg is already installed in the container.');
  } catch (error) {
    console.error('Borg is not installed in the container. Attempting to install it...');
    const installChoice = await askQuestion('Would you like to install Borg in the container? [y/N]: ');
    if (installChoice.trim().toLowerCase() === 'y') {
      console.log('Installing Borg in the Docker container...');
      await $`docker exec -e BORG_PASSPHRASE=${process.env.BORG_PASSPHRASE} ${DOCKER_CONTAINER_NAME} sh -c "apk add --no-cache borgbackup"`; // For Alpine containers
    } else {
      console.error('Borg is required for this backup script. Exiting...');
      process.exit(1);
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
  const repoExists = await $`docker exec -e BORG_PASSPHRASE=${process.env.BORG_PASSPHRASE} ${DOCKER_CONTAINER_NAME} borg list ${backupConfig.repoDir} || true`;
  if (!repoExists.stdout) {
    await $`docker exec -e BORG_PASSPHRASE=${process.env.BORG_PASSPHRASE} ${DOCKER_CONTAINER_NAME} borg init --encryption=repokey /borg_repo`;
  }
}

// Function to back up Docker volumes
async function backupVolumes() {
  const { stdout: volumesStdout } = await $`docker volume ls -q`;
  const volumes = volumesStdout.trim().split('\n').filter(volume => volume);

  for (const volume of volumes) {
    console.log(`Backing up volume: ${volume}`);

    try {
      // Get the mount point of the volume
      const { stdout: mountpointStdout } = await $`docker volume inspect --format '{{.Mountpoint}}' ${volume}`;
      const mountpoint = mountpointStdout.trim();

      // Check if the mount point exists before backing it up
      if (mountpoint) {
        console.log(`Backing up volume from path: ${mountpoint}`);

        // Perform the backup inside the Borg container
        await $`docker exec -e BORG_PASSPHRASE=${process.env.BORG_PASSPHRASE} ${DOCKER_CONTAINER_NAME} borg create --stats --progress /borg_repo::${volume}_${TIMESTAMP} ${mountpoint}`;
      } else {
        console.error(`Mount point not found for volume: ${volume}`);
      }
    } catch (error) {
      console.error(`Failed to back up volume: ${volume}`);
      handleError(error); // Ensure error handling for failed backups
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
    const bindMountName = bindMount.replace(/[\/\\]/g, '_'); // Sanitize bind mount name
    console.log(`Backing up bind mount: ${bindMount}`);
    try {
      await $`docker run --rm -v ${bindMount}:/bind -v ${backupConfig.baseDir}/borg_repo:${backupConfig.repoDir} \
        -e BORG_PASSPHRASE=${process.env.BORG_PASSPHRASE} ${DOCKER_CONTAINER_NAME} \
        borg create --stats --progress ${backupConfig.repoDir}::${bindMountName}_${TIMESTAMP} /bind`;
    } catch (error) {
      console.error(`Failed to back up bind mount: ${bindMount}`);
      handleError(error);
    }
  }
}

// Function to back up Docker containers
async function backupContainers() {
  const { stdout: containersStdout } = await $`docker ps -q`;
  const containerIds = containersStdout.trim().split('\n').filter(id => id);

  for (const containerId of containerIds) {
    const { stdout: containerName } = await $`docker inspect --format='{{.Name}}' ${containerId}`;
    const sanitizedContainerName = containerName.replace(/^\//, '');

    console.log(`Backing up container: ${sanitizedContainerName}`);
    try {
      await $`docker export ${containerId} | docker exec -e BORG_PASSPHRASE=${process.env.BORG_PASSPHRASE} -i ${DOCKER_CONTAINER_NAME} borg create --stats --progress /borg_repo::${sanitizedContainerName}_${TIMESTAMP} -`;
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
    const sanitizedImageName = image.replace(/[\/:]/g, '_');
    console.log(`Backing up image: ${image}`);
    try {
      await $`docker save ${image} | docker exec -e BORG_PASSPHRASE=${process.env.BORG_PASSPHRASE} -i ${DOCKER_CONTAINER_NAME} borg create --stats --progress /borg_repo::${sanitizedImageName}_${TIMESTAMP} -`;
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
    const sanitizedNetworkName = networkName.replace(/[\/:]/g, '_');

    console.log(`Backing up network: ${networkName}`);
    try {
      await $`docker network inspect ${networkId} | docker exec -e BORG_PASSPHRASE=${process.env.BORG_PASSPHRASE} -i ${DOCKER_CONTAINER_NAME} borg create --stats --progress /borg_repo::${sanitizedNetworkName}_${TIMESTAMP} -`;
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
    const sanitizedContainerName = containerName.replace(/^\//, '');

    console.log(`Backing up environment variables for container: ${sanitizedContainerName}`);
    try {
      const { stdout: envVars } = await $`docker inspect --format='{{range .Config.Env}}{{.}} {{end}}' ${containerId}`;
      const envVarsArray = envVars.split(' ').filter(Boolean);
      await $`echo ${JSON.stringify(envVarsArray, null, 2)} | docker exec -e BORG_PASSPHRASE=${process.env.BORG_PASSPHRASE} -i ${DOCKER_CONTAINER_NAME} borg create --stats --progress /borg_repo::${sanitizedContainerName}_env_vars_${TIMESTAMP} -`;
    } catch (error) {
      console.error(`Failed to back up environment variables for container: ${sanitizedContainerName}`);
      handleError(error);
    }
  }
}

// Cleanup function to remove old backups
async function cleanupOldBackups() {
  const daysToKeep = 30;
  console.log(`Cleaning up old backups... Keeping backups for the last ${daysToKeep} days.`);
  try {
    await $`docker exec -e BORG_PASSPHRASE=${process.env.BORG_PASSPHRASE} ${DOCKER_CONTAINER_NAME} borg prune --keep-daily=${daysToKeep} --keep-weekly=4 --keep-monthly=6 /borg_repo`;
    console.log('Cleanup completed successfully.');
  } catch (error) {
    console.error('Failed to clean up old backups.');
    handleError(error);
  }
}

// Main script execution
(async () => {
  await checkRootUser(); // Call the checkRootUser function at the start
  await setPassphrase(); // Ensure the passphrase is set
  await createBackupDirectory() // Create backup directory
  await ensurePermissions()
  await checkContainerExistence()
  await checkBorgBackupDockerInstallationInContainer(); // Check if Borg is installed in the Docker container
  await createBackupDirectories(); // Create all backup directories before trying to initialize the Borg repository
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
