#!/usr/local/bin/zx

import { $ } from 'zx'
import path from 'path'

if (process.argv.length < 3) {
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

