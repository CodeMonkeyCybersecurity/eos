#!/usr/bin/env zx

// Create the backup directory if it doesn't exist
const backupDir = '~/docker_dockerfiles_backups';
await $`mkdir -p ${backupDir}`;

// Specify the path to your project directories
const projectDirs = ['./your_project_dir1', './your_project_dir2'];

// Loop through each project directory to find Dockerfiles
for (const dir of projectDirs) {
    const dockerFiles = await $`find ${dir} -name 'Dockerfile'`;
    const dirs = await $`find ${dir} -name '.'`;
    
    for (const file of dockerFiles.stdout.split('\n').filter(Boolean)) {
        console.log(`Backing up Dockerfile: ${file}`);
        await $`cp ${file} ${backupDir}/`;
    }

    // Optionally back up the context (e.g., all files in the directory containing the Dockerfile)
    for (const dir of dirs.stdout.split('\n').filter(Boolean)) {
        console.log(`Backing up build context for: ${dir}`);
        await $`cp -r ${dir}/* ${backupDir}/`;
    }
}

console.log('Dockerfiles and build context backup completed successfully!');
