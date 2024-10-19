#!/usr/bin/env zx

const backupDir = `/opt/backups/dockerBackups/docker_dockerfiles_backups`;  // Adjust this path as needed

// Function to check if the script is run with sudo/root
function checkRootUser() {
  if (process.getuid && process.getuid() !== 0) {
    console.error("This script must be run with sudo or as root.");
    process.exit(1); // Exit if not run as root
  }
}

// Main function to run the script logic
async function main() {
  // Check if the script is run as root
  checkRootUser();
    
  // Create the backup directory if it doesn't exist
  await $`mkdir -p ${backupDir}`;

  // Specify the path to your project directories
  const projectDirs = ['./your_project_dir1', './your_project_dir2'];

  // Loop through each project directory to find Dockerfiles
  for (const projectDir of projectDirs) {
    const dockerFiles = await $`find ${projectDir} -name 'Dockerfile'`;

    // Backup Dockerfiles
    for (const file of dockerFiles.stdout.split('\n').filter(Boolean)) {
      console.log(`Backing up Dockerfile: ${file}`);
      const projectBackupDir = `${backupDir}/${projectDir}`;
      await $`mkdir -p ${projectBackupDir}`;  // Create subdir for each project
      await $`cp ${file} ${projectBackupDir}/`;
    }

    // Backup the context (all files in the directory containing the Dockerfile)
    const dockerfileDirs = await $`find ${projectDir} -name '.'`;

    for (const dir of dockerfileDirs.stdout.split('\n').filter(Boolean)) {
      console.log(`Backing up build context for: ${dir}`);
      const projectBackupDir = `${backupDir}/${projectDir}`;
      await $`cp -r ${dir}/* ${projectBackupDir}/`;
    }
  }

  console.log('Dockerfiles and context backup completed successfully!');
}

// Call the main function
await main();
