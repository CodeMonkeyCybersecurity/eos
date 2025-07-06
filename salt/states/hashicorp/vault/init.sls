# salt/states/hashicorp/vault/init.sls
# HashiCorp Vault state initialization

include:
  - hashicorp.vault.install
  - hashicorp.vault.config
  - hashicorp.vault.service