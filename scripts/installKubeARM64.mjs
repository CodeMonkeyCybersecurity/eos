#!/usr/bin/env zx

// Function to install kubectl
async function installKubectl() {
    console.log('Installing kubectl...');
    await $`sudo apt-get update`;
    await $`sudo apt-get install -y apt-transport-https ca-certificates curl gnupg`;
    await $`curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.31/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg`;
    await $`sudo chmod 644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg`;
    await $`echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.31/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list`;
    await $`sudo chmod 644 /etc/apt/sources.list.d/kubernetes.list`;
    await $`sudo apt-get update`;
    await $`sudo apt-get install -y kubectl`;
    console.log('kubectl for linux arm64 installed successfully.');
}

// Main function to run the installation process
async function main() {
    await installKubectl();
    console.log('Kubernetes setup complete!');
}

main().catch(err => {
    console.error('Error during installation:', err);
});
