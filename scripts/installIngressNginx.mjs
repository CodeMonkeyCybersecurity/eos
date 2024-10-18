#!/usr/bin/env zx

async function installHelm() {
    console.log('Adding ingress-nginx using Helm...');
    await $`helm upgrade --install ingress-nginx ingress-nginx --repo https://kubernetes.github.io/ingress-nginx  --namespace ingress-nginx --create-namespace`;
    console.log('Ingress-nginx installed successfully.');
}

installHelm().catch(err => {
    console.error('Error during installation:', err);
});
