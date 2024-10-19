#!/usr/bin/env zx

// checkSudo.mjs
export async function checkRootUser() {
  if (process.getuid && process.getuid() !== 0) {
    console.log('checking user has sudo or root permissions');
    console.error("This script must be run with sudo or as root.");
    process.exit(1); // Exit if not run as root
  }
}
