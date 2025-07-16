# salt/states/hashicorp/vault/init.sls
# HashiCorp Vault state initialization

# Standard Vault installation (compatible with existing systems)
include:
  - hashicorp.vault.install
  - hashicorp.vault.config
  - hashicorp.vault.service