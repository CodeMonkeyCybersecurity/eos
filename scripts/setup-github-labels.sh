#!/bin/bash
# Setup GitHub labels for the Eos repository
# This script creates the labels defined in .github/labeler.yml

set -e

REPO="${1:-CodeMonkeyCybersecurity/eos}"

echo " Setting up GitHub labels for repository: $REPO"

# Check if gh CLI is available
if ! command -v gh &> /dev/null; then
    echo " GitHub CLI (gh) is required but not installed"
    echo "Install it from: https://cli.github.com/"
    exit 1
fi

# Check if authenticated
if ! gh auth status &> /dev/null; then
    echo " Not authenticated with GitHub CLI"
    echo "Run: gh auth login"
    exit 1
fi

echo " GitHub CLI authenticated"

# Define labels based on .github/labeler.yml
declare -A LABELS=(
    ["documentation"]=" Documentation updates"
    ["cli"]=" CLI commands and interface"
    ["ansible"]=" Ansible playbooks and automation"
    ["scripts"]=" Shell scripts and utilities"
    ["pkg-container"]=" Container and Docker packages"
    ["pkg-vault"]=" HashiCorp Vault integration"
    ["pkg-kvm"]=" KVM virtualization"
    ["pkg-delphi"]=" Delphi monitoring platform"
    ["pkg-crypto"]=" Cryptographic functions"
    ["pkg-hecate"]=" Hecate reverse proxy/mail"
    ["pkg-ldap"]=" LDAP directory services"
    ["pkg-mattermost"]=" Mattermost integration"
    ["pkg-platform"]=" Platform abstraction layer"
    ["pkg-utils"]=" Utility packages and helpers"
    ["pkg-other"]=" Other package changes"
    ["ci"]=" CI/CD workflows and configuration"
    ["dependencies"]=" Dependency updates"
    ["policies"]=" Policy definitions (OPA/CUE)"
    ["sql"]=" Database schemas and SQL"
)

# Color scheme for labels
declare -A COLORS=(
    ["documentation"]="0052cc"
    ["cli"]="7057ff"
    ["ansible"]="ee0701"
    ["scripts"]="c2e0c6"
    ["pkg-container"]="006b75"
    ["pkg-vault"]="bfd4f2"
    ["pkg-kvm"]="d4c5f9"
    ["pkg-delphi"]="f9d0c4"
    ["pkg-crypto"]="c5def5"
    ["pkg-hecate"]="fef2c0"
    ["pkg-ldap"]="0e8a16"
    ["pkg-mattermost"]="fbca04"
    ["pkg-platform"]="d93f0b"
    ["pkg-utils"]="b60205"
    ["pkg-other"]="5319e7"
    ["ci"]="ffffff"
    ["dependencies"]="0366d6"
    ["policies"]="e99695"
    ["sql"]="f9c513"
)

echo "Creating labels..."

for label in "${!LABELS[@]}"; do
    description="${LABELS[$label]}"
    color="${COLORS[$label]}"
    
    echo " Creating label: $label"
    
    # Try to create the label, ignore if it already exists
    gh label create "$label" \
        --description "$description" \
        --color "$color" \
        --repo "$REPO" 2>/dev/null || echo "   Label '$label' already exists"
done

echo ""
echo " GitHub labels setup complete!"
echo ""
echo " Next steps:"
echo "1. Re-enable the labeler workflow in .github/workflows/label.yml"
echo "2. Uncomment the pull_request trigger"
echo "3. Labels will be automatically applied to PRs based on file paths"