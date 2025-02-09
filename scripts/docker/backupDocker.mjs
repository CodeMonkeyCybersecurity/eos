#!/usr/bin/env zx

const path = require('path');

// Define the directory where your sub-scripts are located
const scriptsDir = path.join(__dirname);

// List of scripts to execute
const scripts = [
  'backupDockerContainers.mjs',
  'backupDockerImages.mjs',
  'backupDockerVolumesWithCp.mjs',
  'backupDockerEnvVars.mjs',
  'backupDockerNetworks.mjs',
  'backupsDockerComposeFiles.mjs',
  'backupDockerfiles.mjs',
  'backupDockerSwarm.mjs'
];

// Execute each script in sequence
for (const script of scripts) {
  try {
    console.log(`Running script: ${script}`);
    await $`zx ${path.join(scriptsDir, script)}`;
    console.log(`Successfully ran script: ${script}`);
  } catch (error) {
    console.error(`Failed to run script: ${script}`);
    console.error(error);
    process.exit(1);  // Exit if any script fails
  }
}

console.log('All backup scripts completed successfully!');
