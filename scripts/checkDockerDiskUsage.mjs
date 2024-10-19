#!/usr/bin/env zx

const { $, echo } = require('zx');

// Function to convert sizes to GB
function convertToGB(size) {
  size = size.replace(/,/g, ''); // Remove commas
  if (size.endsWith('GB')) return parseFloat(size);
  if (size.endsWith('MB')) return parseFloat(size) / 1024;
  if (size.endsWith('KB')) return parseFloat(size) / (1024 * 1024);
  return 0;
}

// Get the output of docker system df
const { stdout } = await $`docker system df --format "{{.Size}}"`;
const sizes = stdout.trim().split('\n');

// Calculate the total disk usage in GB
let total = sizes.reduce((sum, size) => sum + convertToGB(size), 0);

// Calculate space needed for safe backup (10x)
let safesize = total * 10;

// Print the total Docker disk usage
echo(`Total Docker Disk Usage: ${total.toFixed(2)} GB`);
echo(`Total space required for safe Docker backup: ${safesize.toFixed(2)} GB`);
