#!/usr/bin/env zx

const { $, echo } = require('zx');

// Main function to check if backup is feasible
async function checkBackupFeasibility() {
  // Run the checkDiskUsage.mjs script and capture its output
  const diskUsageOutput = (await $`zx checkDiskUsage.mjs`).stdout;
  const availableDiskMatch = diskUsageOutput.match(/Total Disk Available: (\d+(\.\d+)?[A-Z])/);
  const availableDisk = availableDiskMatch ? availableDiskMatch[1] : null;

  // Run the checkDockerDiskUsage.mjs script and capture its output
  const dockerUsageOutput = (await $`zx checkDockerDiskUsage.mjs`).stdout;
  const safeBackupMatch = dockerUsageOutput.match(/Total space required for safe Docker backup: (\d+(\.\d+)? [A-Z]+)/);
  const safeBackupSize = safeBackupMatch ? safeBackupMatch[1] : null;

  if (!availableDisk || !safeBackupSize) {
    echo('Error: Could not extract disk usage or safe backup size.');
    return;
  }

  // Convert availableDisk and safeBackupSize to GB
  function convertToGB(size) {
    size = size.replace(/,/g, ''); // Remove commas
    if (size.endsWith('G')) return parseFloat(size);
    if (size.endsWith('T')) return parseFloat(size) * 1024;
    return 0; // Return 0 if unhandled case
  }

  const availableDiskGB = convertToGB(availableDisk);
  const safeBackupSizeGB = convertToGB(safeBackupSize);

  // Determine if backup is feasible
  const isFeasible = availableDiskGB > safeBackupSizeGB;
  echo(`Is there enough space for the Docker backup? ${isFeasible}`);
}

// Run the main function
await checkBackupFeasibility();
