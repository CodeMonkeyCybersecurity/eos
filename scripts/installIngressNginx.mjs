#!/usr/bin/env zx

// Define the necessary Helm command and arguments
const helmCommand = [
  'helm', 'upgrade', '--install', 'ingress-nginx', 'ingress-nginx',
  '--repo', 'https://kubernetes.github.io/ingress-nginx',
  '--namespace', 'ingress-nginx', '--create-namespace'
];

// Execute the Helm command
await $`${helmCommand}`;
