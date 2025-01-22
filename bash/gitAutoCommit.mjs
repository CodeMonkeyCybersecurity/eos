#!/usr/bin/env zx

import { question } from 'zx';

// Function to run shell commands
async function runCommand(command) {
  try {
    return await $`${command}`.quiet();
  } catch {
    return '';
  }
}

// Main function
(async function main() {
  // Check if git email is set
  let gitEmail = await runCommand('git config --get user.email');
  let gitName = await runCommand('git config --get user.name');

  // If email is not set, prompt user for email and set it
  if (!gitEmail.trim()) {
    console.log('Git user.email is not set.');
    gitEmail = await question('Please enter your email: ');
    await $`git config --global user.email ${gitEmail}`;
    console.log(`Git user.email set to ${gitEmail}`);
  }

  // If name is not set, prompt user for name and set it
  if (!gitName.trim()) {
    console.log('Git user.name is not set.');
    gitName = await question('Please enter your name: ');
    await $`git config --global user.name ${gitName}`;
    console.log(`Git user.name set to ${gitName}`);
  }

  // Check for commit message or prompt the user for one
  const commitMessage = process.argv[2] || await question('Please enter your commit message: ');

  try {
    await $`git add .`;
    await $`git commit -m ${commitMessage}`;
    await $`git push`;
    console.log('Changes have been pushed to the repository.');
  } catch (error) {
    console.error('Error committing or pushing changes:', error.message);
  }
})();
