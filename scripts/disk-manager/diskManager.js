const shell = require('shelljs');
const drivelist = require('drivelist');
const inquirer = require('inquirer');

// List available disks
async function listDisks() {
  const drives = await drivelist.list();
  drives.forEach((drive) => {
    console.log(`Device: ${drive.device}`);
    console.log(`Description: ${drive.description}`);
    console.log(`Size: ${drive.size}`);
    console.log(`Mountpoints: ${JSON.stringify(drive.mountpoints, null, 2)}`);
    console.log('---');
  });
}

// Create a new partition
function createPartition(disk) {
  if (!shell.which('fdisk')) {
    shell.echo('Sorry, fdisk is not installed');
    shell.exit(1);
  }

  shell.exec(`(echo n; echo p; echo 1; echo; echo; echo w) | sudo fdisk ${disk}`, (code, stdout, stderr) => {
    if (code !== 0) {
      console.error(`Error creating partition: ${stderr}`);
    } else {
      console.log(`Partition created on ${disk}: ${stdout}`);
    }
  });
}

// Format a partition as ext4
function formatPartition(partition) {
  if (!shell.which('mkfs.ext4')) {
    shell.echo('Sorry, mkfs.ext4 is not installed');
    shell.exit(1);
  }

  shell.exec(`sudo mkfs.ext4 ${partition}`, (code, stdout, stderr) => {
    if (code !== 0) {
      console.error(`Error formatting partition: ${stderr}`);
    } else {
      console.log(`Partition formatted as ext4: ${stdout}`);
    }
  });
}

// Mount a partition
function mountPartition(partition, mountPoint) {
  if (!shell.which('mount')) {
    shell.echo('Sorry, mount is not installed');
    shell.exit(1);
  }

  shell.exec(`sudo mount ${partition} ${mountPoint}`, (code, stdout, stderr) => {
    if (code !== 0) {
      console.error(`Error mounting partition: ${stderr}`);
    } else {
      console.log(`Partition mounted at ${mountPoint}: ${stdout}`);
    }
  });
}

// Get user input and perform actions
async function getUserInput() {
  await listDisks();

  const answers = await inquirer.prompt([
    {
      type: 'input',
      name: 'disk',
      message: 'Enter the disk you want to partition (e.g., /dev/sdb):',
    },
    {
      type: 'input',
      name: 'mountPoint',
      message: 'Enter the mount point for the partition (e.g., /mnt/data):',
    },
  ]);

  createPartition(answers.disk);
  formatPartition(`${answers.disk}1`);
  mountPartition(`${answers.disk}1`, answers.mountPoint);
}

getUserInput();
