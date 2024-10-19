#!/usr/bin/env zx

// Create the backup directory if it doesn't exist
const backupDir = '~/docker_env_vars_backups';
await $`mkdir -p ${backupDir}`;

// List all Docker containers
const containers = await $`docker ps -aq`;

// Loop through each container and back up its environment variables
for (const container of containers.stdout.split('\n').filter(Boolean)) {
    console.log(`Backing up environment variables for container: ${container}`);
    const envVars = await $`docker inspect -f '{{ .Config.Env }}' ${container}`;
    const envFile = `${backupDir}/${container}_env_vars.txt`;
    await $`echo ${envVars.stdout} > ${envFile}`;
}

console.log('Environment variables backup completed successfully!');
