#!/usr/bin/env zx

// Create the backup directory if it doesn't exist
const backupDir = '~/docker_swarm_backups';
await $`mkdir -p ${backupDir}`;

// List all Docker services in the swarm
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

console.log('Swarm backup completed successfully!');
