#!/usr/bin/env zx

import fs from 'fs'
import path from 'path'

export async function logError(errorMessage) {
  const logDir = path.resolve('./logs')
  const logFile = path.join(logDir, 'error.log')

  // Create the logs directory if it doesn't exist
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true })
  }

  const timestamp = new Date().toISOString()
  const logEntry = `[${timestamp}] ERROR: ${errorMessage}\n`

  // Append the error message to the log file
  fs.appendFileSync(logFile, logEntry, 'utf8')

  console.error(`An error occurred: ${errorMessage}`)
}
