#!/usr/bin/env zx

const os = require('os');
const homeDir = os.homedir();

// Define your Docker container name or ID
const DOCKER_CONTAINER_NAME = 'borgBackupDocker'; // Replace with your actual container name or ID

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

// Function to check if the Borg container exists
async function checkBorgBackupDockerContainerExistence() {
  const { stdout: containerList } = await $`docker ps -a --format "{{.Names}}"`;
  const containers = containerList.trim().split('\n');

  if (!containers.includes(DOCKER_CONTAINER_NAME)) {
    console.log(`Container "${DOCKER_CONTAINER_NAME}" does not exist. Creating it...`);
    await $`docker run -d --name ${DOCKER_CONTAINER_NAME} alpine sh -c "while true; do sleep 30; done"`; // Create an Alpine container that runs indefinitely
  } else {
    console.log(`Container "${DOCKER_CONTAINER_NAME}" already exists.`);
  }
}

// Function to check if Borg is installed in the Docker container
async function checkBorgBackupDockerInstallationInContainer() {
  try {
    await $`docker exec ${DOCKER_CONTAINER_NAME} borg --version`;
  } catch (error) {
    console.error('Borg is not installed in the container. Attempting to install it...');
    const installChoice = await $`read -p "Would you like to install Borg in the container? [y/N]: " choice; echo $choice`;
    if (installChoice.trim().toLowerCase() === 'y') {
      console.log('Installing Borg in the Docker container...');
      await $`docker exec ${DOCKER_CONTAINER_NAME} sh -c "apk add --no-cache borgbackup"`; // For Alpine containers
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
      await $`docker run --rm -v ${volume}:/volume alpine sh -c "borg create --stats --progress ${backupConfig.repoDir}::${volume}_${TIMESTAMP} /volume"`;
    } catch (error) {
      console.error(`Failed to back up volume: ${volume}`);
      console.error(error);
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
      await $`borg create --stats --progress ${backupConfig.repoDir}::${bindMountName}_${TIMESTAMP} ${bindMount}`;
    } catch (error) {
      console.error(`Failed to back up bind mount: ${bindMount}`);
      console.error(error);
    }
  }
}

// Function to back up Docker containers
async function backupContainers() {
  const { stdout: containersStdout } = await $`docker ps -q`;
  const containerIds = containersStdout.trim().split('\n').filter(id => id);

  for (const containerId of containerIds) {
    const containerName = await $`docker inspect --format='{{.Name}}' ${containerId}`;
    const sanitizedContainerName = containerName.replace(/^\//, ''); // Remove leading slash

    console.log(`Backing up container: ${sanitizedContainerName}`);
    try {
      await $`docker export ${containerId} | gzip > ${backupConfig.containers}/${sanitizedContainerName}_${TIMESTAMP}.tar.gz`;
    } catch (error) {
      console.error(`Failed to back up container: ${sanitizedContainerName}`);
      console.error(error);
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
      await $`docker save ${image} | gzip > ${backupConfig.images}/${sanitizedImageName}_${TIMESTAMP}.tar.gz`;
    } catch (error) {
      console.error(`Failed to back up image: ${image}`);
      console.error(error);
    }
  }
}

// Function to back up Docker networks
async function backupNetworks() {
  const { stdout: networksStdout } = await $`docker network ls -q`;
  const networkIds = networksStdout.trim().split('\n').filter(id => id);

  for (const networkId of networkIds) {
    // Get network name and inspect
    const { stdout: networkName } = await $`docker network inspect ${networkId} --format '{{.Name}}'`;
    const sanitizedNetworkName = networkName.replace(/[\/:]/g, '_'); // Replace slashes and colons for a valid filename

    console.log(`Backing up network: ${networkName}`);
    try {
      // Save the network configuration as JSON
      await $`docker network inspect ${networkId} > ${backupConfig.networks}/${sanitizedNetworkName}.json`;
    } catch (error) {
      console.error(`Failed to back up network: ${networkName}`);
      console.error(error);
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
      // Retrieve environment variables
      const { stdout: envVars } = await $`docker inspect --format='{{range .Config.Env}}{{.}} {{end}}' ${containerId}`;
      const envVarsArray = envVars.split(' ').filter(Boolean); // Split and filter empty values

      // Save to a JSON file
      await $`echo ${JSON.stringify(envVarsArray)} > ${backupConfig.envVars}/${sanitizedContainerName}_env_vars.json`;
    } catch (error) {
      console.error(`Failed to back up environment variables for container: ${sanitizedContainerName}`);
      console.error(error);
    }
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

  console.log('Backup completed successfully!');
})();
