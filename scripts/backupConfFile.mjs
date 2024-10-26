#!/usr/bin/env zx

import { $ } from 'zx'
import path from 'path'

console.log("Arguments provided:", process.argv) // Argument Debugging: console.log("Arguments provided:", process.argv) will show the list of arguments passed to the script when it runs.

const args = process.argv.slice(2) // Ensure only user-specified arguments are processed

// Check if <file_to_backup> is specified as an argument
if (args.length < 1) { //check if args.length is less than 1 to know that no <file_to_backup> argument was provided.
  console.error("Usage: zx backupConfFile.mjs <file_to_backup>")
  process.exit(1)
}

const fileToBackup = args[0]
const dir = path.dirname(fileToBackup)
const filename = path.basename(fileToBackup)
const date = new Date().toISOString().split('T')[0]  // YYYY-MM-DD format
const time = new Date().toLocaleTimeString('en-GB', { hour12: false }).replace(/:/g, '')  // HHMMSS format

const backupFile = `${dir}/${filename}.backup.${date}${time}`

// Copy the file to a backup location
await $`cp ${fileToBackup} ${backupFile}`
console.log(`Backup created: ${backupFile}`)
console.log(`Keep humans in the loop`)
