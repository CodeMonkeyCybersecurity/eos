#!/usr/bin/env zx

async function installHelm() {
    console.log('Adding Helm GPG key...');
    await $`curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null`;
    
    console.log('Installing apt-transport-https...');
    await $`sudo apt-get install apt-transport-https --yes`;
    
    console.log('Adding Helm repository...');
    await $`echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list`;
    
    console.log('Updating package lists...');
    await $`sudo apt-get update`;
    
    console.log('Installing Helm...');
    await $`sudo apt-get install helm --yes`;
    
    console.log('Helm installed successfully.');
}

installHelm().catch(err => {
    console.error('Error during installation:', err);
});
