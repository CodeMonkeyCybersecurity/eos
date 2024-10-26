#!/usr/bin/env zx

import { $ } from 'zx'
import path from 'path'

// Logging
console.log("Arguments provided:", process.argv) // Argument Debugging: console.log("Arguments provided:", process.argv) will show the list of arguments passed to the script when it runs.

// Check if <file_to_backup> is specified as an argument
if (process.argv.length < 3 || !process.argv[2]) { //Additional Check: The condition if (process.argv.length < 3 || !process.argv[2]) ensures the script exits if <file_to_backup> is missing.
  console.error("Usage: zx backupConfFile.mjs <file_to_backup>")
  process.exit(1)
}

const fileToBackup = process.argv[2]
const dir = path.dirname(fileToBackup)
const filename = path.basename(fileToBackup)
const date = new Date().toISOString().split('T')[0]  // YYYY-MM-DD format
const time = new Date().toLocaleTimeString('en-GB', { hour12: false }).replace(/:/g, '')  // HHMMSS format

const backupFile = `${dir}/${filename}.backup.${date}${time}`

// Copy the file to a backup location
await $`cp ${fileToBackup} ${backupFile}`
console.log(`Backup created: ${backupFile}`)
