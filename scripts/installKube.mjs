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
    console.log('kubectl installed successfully.');
}

// Function to install Minikube for ARM64
async function installMinikube() {
    console.log('Installing Minikube...');
    await $`curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-arm64`;
    await $`sudo install minikube-linux-arm64 /usr/local/bin/minikube`;
    await $`rm minikube-linux-arm64`;
    console.log('Minikube installed successfully.');
}

// Main function to run the installation process
async function main() {
    await installKubectl();
    await installMinikube();
    console.log('Kubernetes setup complete!');
}

main().catch(err => {
    console.error('Error during installation:', err);
});
