#!/usr/bin/env zx

// Try to load required packages and handle missing module errors gracefully
let yaml;
let argparse;
let luxon;
try {
  yaml = await import('js-yaml');
  argparse = await import('argparse');
  luxon = await import('luxon');
} catch (error) {
  if (error.code === 'ERR_MODULE_NOT_FOUND') {
    const missingPackage = error.message.match(/'([^']+)'/)[1];
    console.error(`Error: Required package '${missingPackage}' is not installed.`);
    console.log(`To resolve this issue, you have two options:`);
    
    console.log(`1. Install the missing package locally (recommended++):`);
    console.log(`\nsudo npm install ${missingPackage}\n`);
    
    console.log(`2. Or install it glocally:`);
    console.log(`\nsudo npm install -g ${missingPackage}\n`);

    console.log(`If you installed the package globally and still encounter issues, check if it is in your $PATH by running:`);
    console.log(`\necho $PATH\n`);
    
    console.log(`If it's not there, you can add the global npm bin directory to your PATH by appending this line to your ~/.bashrc or ~/.zshrc file (depending on your shell):`);
    console.log(`\nexport PATH=$PATH:$(npm bin -g)\n`);
    console.log(`export PATH=$PATH:/usr/local/lib/node_modules`);

    console.log(`After adding this, reload your shell with the following command:`);
    console.log(`\nsource ~/.bashrc  # or ~/.zshrc if you're using Zsh\n`);

    console.log(`You can also verify that Node.js can access the global'${missingPackage}' by running: `);
    console.log(`node -e "require('js-yaml')"`);

    process.exit(1);
  } else {
    console.error(`An unexpected error occurred: ${error.message}`);
    process.exit(1);
  }
}
// Check if the script is being run with sudo
if (process.getuid && process.getuid() !== 0) {
  console.error('Error: This script must be run with sudo privileges. Please rerun the script with "sudo".');
  process.exit(1);
}

// Rest of your script here...
import { promises as fs } from 'fs';
import { hostname } from 'os';

// Path to the YAML configuration file
const CONFIG_PATH = '/etc/eos/borg_config.yaml';

// Load the configuration file
async function loadConfig() {
  try {
    if (await fs.stat(CONFIG_PATH)) {
      const content = await fs.readFile(CONFIG_PATH, 'utf8');
      return yaml.load(content);
    }
  } catch (error) {
    console.error(`Error loading configuration: ${error.message}`);
    return null;
  }
}

// Check if required values are set in the YAML config
function checkYamlConfig(config) {
  const requiredValues = {
    'borg.repo': config?.borg?.repo,
    'borg.passphrase': config?.borg?.passphrase,
    'borg.encryption': config?.borg?.encryption,
    'backup.paths_to_backup': config?.backup?.paths_to_backup,
  };

  for (const [key, value] of Object.entries(requiredValues)) {
    if (!value) {
      console.error(`Configuration issue: '${key}' is not set.`);
      return false;
    }
  }
  console.info('All required configuration values are set.');
  return true;
}

// Check the health of the Borg repository
async function checkRepo(config) {
  const { repo, passphrase } = config.borg;
  process.env.BORG_PASSPHRASE = passphrase;

  try {
    await $`borg check ${repo}`;
    console.log('Repository check passed.');
    return true;
  } catch (error) {
    console.error(`Repository check failed: ${error.stderr}`);
    return false;
  }
}

// Run the Borg backup
async function runBorgBackup(config, dryrun = false) {
  const { repo, passphrase } = config.borg;
  const paths = config.backup.paths_to_backup;
  const compression = config.backup.compression || 'lz4';
  const archiveName = `${repo}::${hostname()}-${luxon.DateTime.now().toFormat('yyyy-MM-ddTHH:mm:ss')}`;

  process.env.BORG_PASSPHRASE = passphrase;

  const borgCreateCmd = [
    'borg', 'create', archiveName,
    ...paths,
    '--verbose', '--filter', config.backup.filter, '--list',
    '--stats', '--show-rc', '--compression', compression, '--exclude-caches',
  ];

  // Add any exclude patterns from config
  config.backup.exclude_patterns?.forEach(pattern => {
    borgCreateCmd.push('--exclude', pattern);
  });

  // Add dry-run if applicable
  if (dryrun) {
    borgCreateCmd.push('--dry-run');
  }

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

// Test restore a Borg archive
async function testRestoreBorgArchive(config, archiveName) {
  const { repo, passphrase } = config.borg;
  process.env.BORG_PASSPHRASE = passphrase;

  try {
    await $`borg extract --dry-run ${repo}::${archiveName}`;
    console.log(`Test restore of archive '${archiveName}' succeeded.`);
  } catch (error) {
    console.error(`Test restore failed: ${error.stderr}`);
  }
}

// Main function to handle the argument parsing and actions
async function main() {
  const parser = new argparse.ArgumentParser({
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

  // Load the YAML configuration
  const config = await loadConfig();
  if (!config) {
    console.error('No valid configuration found.');
    return;
  }

  // Handle each argument
  if (args.check_yaml) {
    checkYamlConfig(config);
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
  } else if (args.test_restore) {
    await testRestoreBorgArchive(config, args.test_restore);
  } else {
    console.log('No valid action specified. Use --help for available options.');
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
