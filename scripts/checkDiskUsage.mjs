#!/usr/bin/env zx

const { $, echo } = require('zx');

// Run the df command and capture the output
const { stdout } = await $`df -h /`;

// Use regex or splitting to parse the Used and Available space
const lines = stdout.trim().split('\n');
const rootLine = lines[1].split(/\s+/);  // Second line corresponds to `/`

const used = rootLine[2];  // Third column is "Used"
const available = rootLine[3];  // Fourth column is "Available"

// Output the result
echo(`Total Disk Usage: ${used}`);
echo(`Total Disk Available: ${available}`);
