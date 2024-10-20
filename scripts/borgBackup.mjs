#!/usr/bin/env zx

import { promises as fs } from 'fs';
import { ArgumentParser } from 'argparse';
import yaml from 'js-yaml';
import { hostname } from 'os';

// Path to the YAML configuration file
const CONFIG_PATH = '/etc/eos/borg_config.yaml';

// Ensure the script is running with sudo
function checkSudo() {
  if (process.getuid && process.getuid() !== 0) {
    console.error('Error: This script must be run with sudo privileges. Please rerun the script with "sudo".');
    process.exit(1);
  }
}

// Load or create the configuration file
async function loadOrCreateConfig() {
  let config;
  try {
    await fs.access(CONFIG_PATH);  // Check if file exists
    const content = await fs.readFile(CONFIG_PATH, 'utf8');
    config = yaml.load(content);
  } catch {
    console.log('No configuration file found. Creating a new one...');
    config = { borg: {}, backup: {} };
    await saveConfig(config);
  }
  return config;
}

// Save the configuration file
async function saveConfig(config) {
  const yamlContent = yaml.dump(config);
  await fs.writeFile(CONFIG_PATH, yamlContent, 'utf8');
  console.log(`Configuration saved to ${CONFIG_PATH}`);
}

// Check if required values are set in the YAML config
async function checkYamlConfig(config) {
  const requiredValues = {
    'borg.repo': config?.borg?.repo,
    'borg.passphrase': config?.borg?.passphrase,
    'borg.encryption': config?.borg?.encryption,
    'backup.paths_to_backup': config?.backup?.paths_to_backup,
  };

  for (const [key, value] of Object.entries(requiredValues)) {
    if (!value) {
      config = await promptForMissingValue(config, key);
    }
  }
  await saveConfig(config);
  console.log('All required configuration values are set.');
  return true;
}

// Prompt user for missing values
async function promptForMissingValue(config, key) {
  const question = `Please enter a value for ${key}: `;
  const value = await questionInput(question);
  const [category, field] = key.split('.');
  config[category][field] = value;
  return config;
}

// Helper function to read user input
async function questionInput(query) {
  return new Promise((resolve) => {
    process.stdout.write(query);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    process.stdin.once('data', (data) => {
      resolve(data.trim());
    });
  });
}

// Check the health of the Borg repository
async function checkRepo(config) {
  const { repo, passphrase } = config.borg;
  process.env.BORG_PASSPHRASE = passphrase;

  try {
    await $`borg check ${repo}`;
    console.log('Repository check passed.');
  } catch (error) {
    console.error(`Repository check failed: ${error.stderr}`);
  }
}

// Run the Borg backup
async function runBorgBackup(config, dryrun = false) {
  const { repo, passphrase } = config.borg;
  const paths = config.backup.paths_to_backup;
  const compression = config.backup.compression || 'lz4';
  const archiveName = `${repo}::${hostname()}-${new Date().toISOString()}`;

  process.env.BORG_PASSPHRASE = passphrase;

  const borgCreateCmd = [
    'borg', 'create', archiveName,
    ...paths,
    '--verbose', '--list', '--stats',
    '--compression', compression, '--exclude-caches',
  ];

  // Add dry-run if applicable
  if (dryrun) borgCreateCmd.push('--dry-run');

  try {
    await $`${borgCreateCmd}`;
    console.log('Backup completed successfully.');
  } catch (error) {
    console.error(`Backup failed: ${error.stderr}`);
  }
}

// List all Borg archives
async function listBorgArchives(config) {
  const { repo, passphrase } = config.borg;
  process.env.BORG_PASSPHRASE = passphrase;

  try {
    await $`borg list ${repo}`;
  } catch (error) {
    console.error(`Listing archives failed: ${error.stderr}`);
  }
}

// Restore a Borg archive
async function restoreBorgArchive(config, archiveName, targetDir) {
  const { repo, passphrase } = config.borg;
  process.env.BORG_PASSPHRASE = passphrase;

  try {
    await $`borg extract ${repo}::${archiveName} --target ${targetDir}`;
    console.log(`Restored archive '${archiveName}' to '${targetDir}'`);
  } catch (error) {
    console.error(`Restoring archive failed: ${error.stderr}`);
  }
}

// Argument parser setup
const parser = new ArgumentParser({
  description: 'Borg Backup Wrapper',
});

parser.add_argument('--check-yaml', { help: 'Check the YAML configuration', action: 'store_true' });
parser.add_argument('--check-repo', { help: 'Check the Borg repository', action: 'store_true' });
parser.add_argument('--dryrun', { help: 'Run a dry run of the backup', action: 'store_true' });
parser.add_argument('--backup', { help: 'Run a full backup', action: 'store_true' });
parser.add_argument('--list', { help: 'List all archives in the repository', action: 'store_true' });
parser.add_argument('--restore', { help: 'Restore a specific archive', type: 'string' });
parser.add_argument('--test-restore', { help: 'Test restore a specific archive', type: 'string' });
parser.add_argument('--target-dir', { help: 'Specify the target directory for the restore', type: 'string' });

const args = parser.parse_args();

// Command loop
async function commandLoop() {
  while (true) {
    const command = await questionInput('Enter a command (or "E" to exit): ');
    if (command.toLowerCase() === 'e' || command.toLowerCase() === 'exit') {
      console.log('Exiting the script.');
      break;
    }

    switch (command) {
      case '--check-yaml':
        await checkYamlConfig(await loadOrCreateConfig());
        break;
      case '--check-repo':
        await checkRepo(await loadOrCreateConfig());
        break;
      case '--dryrun':
        await runBorgBackup(await loadOrCreateConfig(), true);
        break;
      case '--backup':
        await runBorgBackup(await loadOrCreateConfig());
        break;
      case '--list':
        await listBorgArchives(await loadOrCreateConfig());
        break;
      default:
        console.log(`Unknown command: ${command}`);
    }
  }
}

// Main function to handle startup and argument parsing
async function main() {
  checkSudo();

  const config = await loadOrCreateConfig();

  if (args.check_yaml) {
    await checkYamlConfig(config);
  } else if (args.check_repo) {
    await checkRepo(config);
  } else if (args.dryrun) {
    await runBorgBackup(config, true);
  } else if (args.backup) {
    await runBorgBackup(config);
  } else if (args.list) {
    await listBorgArchives(config);
  } else if (args.restore) {
    if (!args.target_dir) {
      console.error('You must specify a --target-dir to restore an archive.');
    } else {
      await restoreBorgArchive(config, args.restore, args.target_dir);
    }
  } else {
    await commandLoop();
  }
}

main().catch(err => {
  console.error('An unexpected error occurred:', err);
  process.exit(1);
});
