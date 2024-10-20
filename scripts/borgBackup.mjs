#!/usr/bin/env zx

import { promises as fs } from 'fs';
import yaml from 'js-yaml';
import readline from 'readline';
import { hostname } from 'os';

// Set the config file path
const configFilePath = '/etc/eos/borg.yaml';

// Function to read user input from terminal
async function promptUser(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

// Function to load YAML config file
async function loadConfig() {
  try {
    const file = await fs.readFile(configFilePath, 'utf8');
    return yaml.load(file);
  } catch (error) {
    return null; // Return null if the file doesn't exist
  }
}

// Function to save YAML config file, ensuring the directory exists
async function saveConfig(config) {
  try {
    // Ensure the /etc/eos directory exists
    await fs.mkdir('/etc/eos', { recursive: true });

    const yamlContent = yaml.dump(config);
    await fs.writeFile(configFilePath, yamlContent, 'utf8');
    console.log(`Configuration saved to ${configFilePath}`);
  } catch (error) {
    console.error("Error saving configuration:", error);
    process.exit(1);
  }
}

// Function to check and create configuration if missing
async function createOrUpdateConfig() {
  let config = await loadConfig();

  if (!config) {
    console.log('No configuration file found. Creating a new one...');
    config = {};
  }

  // Ask for repository path
  if (!config.borg || !config.borg.repo) {
    config.borg = config.borg || {};
    config.borg.repo = await promptUser("Enter the Borg repository path (e.g., user@backup-server:/path/to/repo): ");
  }

  // Ask for passphrase
  if (!config.borg.passphrase) {
    config.borg.passphrase = await promptUser("Enter the Borg passphrase: ");
  }

  // Ask for paths to back up
  if (!config.backup || !config.backup.paths_to_backup) {
    config.backup = config.backup || {};
    config.backup.paths_to_backup = (await promptUser("Enter the directories to back up (comma-separated): ")).split(',');
  }

  // Ask for exclude patterns
  if (!config.backup.exclude_patterns) {
    config.backup.exclude_patterns = (await promptUser("Enter exclude patterns (comma-separated, e.g., /home/*/.cache/*): ")).split(',');
  }

  // Save the configuration
  await saveConfig(config);

  return config;
}

// Function to run Borg backup
async function runBackup(config) {
  const backupDirs = config.backup.paths_to_backup.join(' ');
  const repo = config.borg.repo;
  const passphrase = config.borg.passphrase;
  const archiveName = `${hostname()}-${Date.now()}`;
  const excludePatterns = config.backup.exclude_patterns;

  if (!passphrase) {
    console.error("Passphrase is not set.");
    process.exit(1);
  }

  // Set the Borg passphrase environment variable
  process.env.BORG_PASSPHRASE = passphrase;

  try {
    const borgBackupCmd = [
      'borg',
      'create',
      '--verbose',
      '--stats',
      '--compression', 'lz4',
      `${repo}::${archiveName}`,
      backupDirs,
      ...excludePatterns.map(pattern => `--exclude ${pattern}`)
    ].join(' ');

    console.log(`Running Borg backup: ${borgBackupCmd}`);
    await $`${borgBackupCmd}`;
    console.log("Backup completed successfully.");
  } catch (error) {
    console.error("Error during backup:", error);
    process.exit(1);
  }
}

// Function to prune old backups
async function pruneArchives(config) {
  try {
    const borgPruneCmd = [
      'borg',
      'prune',
      '--keep-daily', '30',
      '--glob-archives', "'{hostname}-*'",
      '--verbose',
      '--stats'
    ].join(' ');

    console.log(`Pruning old backups: ${borgPruneCmd}`);
    await $`${borgPruneCmd}`;
    console.log("Prune completed successfully.");
  } catch (error) {
    console.error("Error during prune:", error);
    process.exit(1);
  }
}

// Main function to run backup and prune operations
async function main() {
  const config = await createOrUpdateConfig();
  await runBackup(config);
  await pruneArchives(config);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
