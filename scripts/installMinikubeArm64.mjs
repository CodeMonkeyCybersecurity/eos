#!/usr/bin/env zx

// Function to install Minikube for ARM64
async function installMinikube() {
    console.log('Installing Minikube...');
    await $`curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube_latest_arm64.deb`;
    await $`sudo dpkg -i minikube_latest_arm64.deb`;
    console.log('minikube installed successfully, starting minikube.');
    await $`minikube start`;
    console.log('minikube started successfully');
}

// Main function to run the installation process
async function main() {
  await installMinikube();
  console.log('minikube setup complete!');
  console.log('finis');
}

main().catch(err => {
    console.error('Error during installation:', err);
});
