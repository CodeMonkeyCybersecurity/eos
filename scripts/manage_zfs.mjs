#!/usr/bin/env zx

import { question } from 'zx'

// Helper function to run commands
async function runCommand(cmd) {
  try {
    await $`${cmd}`;
  } catch (error) {
    console.error(`Error executing command: ${error}`);
  }
}

// Menu for ZFS management
async function mainMenu() {
  console.log("Select an operation:");
  console.log("1. List ZFS Pools");
  console.log("2. List ZFS Filesystems");
  console.log("3. Expand a Pool");
  console.log("4. Destroy a Pool");
  console.log("5. Destroy a Filesystem");
  console.log("6. Exit");

  const choice = await question("Enter your choice (1-6): ");

  switch (choice) {
    case "1":
      await runCommand("zpool list");
      break;
    case "2":
      await runCommand("zfs list");
      break;
    case "3":
      const expandPoolName = await question("Enter the pool name to expand: ");
      const deviceToAdd = await question("Enter the device to add (e.g., /dev/sdY): ");
      await runCommand(`zpool add ${expandPoolName} ${deviceToAdd}`);
      break;
    case "4":
      const destroyPoolName = await question("Enter the pool name to destroy: ");
      await runCommand(`zpool destroy ${destroyPoolName}`);
      break;
    case "5":
      const destroyFilesystemName = await question("Enter the filesystem name to destroy (e.g., pool_name/dataset_name): ");
      await runCommand(`zfs destroy ${destroyFilesystemName}`);
      break;
    case "6":
      console.log("Exiting...");
      process.exit(0);
    default:
      console.log("Invalid choice. Please select a valid option.");
  }

  // Return to the main menu
  await mainMenu();
}

// Run the main menu
await mainMenu();
