#!/usr/bin/env zx

import { question } from 'zx'
import { $ } from 'zx'
import path from 'path'

// Check if <file_to_backup> is specified
let fileToBackup = process.argv[2]

if (!fileToBackup) {
  console.error("No file specified for backup.")
  // Prompt the user to enter a file path if not provided as an argument
  fileToBackup = await question("Please enter the path to the file you want to back up: ")
  if (!fileToBackup) {
    console.error("No file specified. Exiting.")
    process.exit(1)
  }
}

const dir = path.dirname(fileToBackup)
const filename = path.basename(fileToBackup)
const date = new Date().toISOString().split('T')[0]  // YYYY-MM-DD format
const time = new Date().toLocaleTimeString('en-GB', { hour12: false }).replace(/:/g, '')  // HHMMSS format

const backupFile = `${dir}/${filename}.backup.${date}${time}`

// Copy the file to a backup location
await $`cp ${fileToBackup} ${backupFile}`
console.log(`Backup created: ${backupFile}`)
