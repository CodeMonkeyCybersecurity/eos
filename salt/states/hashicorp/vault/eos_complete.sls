# Eos Complete Vault Installation
# Replicates the full vault.OrchestrateVaultCreate() functionality via Salt states
# This orchestrates all phases: Install -> Environment -> TLS -> Config -> Service -> Initialize

include:
  - hashicorp.vault.install        # Phase 1: PhaseInstallVault + PrepareEnvironment  
  - hashicorp.vault.tls            # Phase 2: GenerateTLS
  - hashicorp.vault.config_eos     # Phase 3: WriteAndValidateConfig  
  - hashicorp.vault.service_eos    # Phase 4: StartVaultService
  - hashicorp.vault.initialize     # Phase 5: InitializeVault

# Final verification that all phases completed successfully
vault_eos_complete_verification:
  cmd.run:
    - name: |
        echo ""
        echo "╔═══════════════════════════════════════════════════════════════════════╗"
        echo "║              EOS VAULT DEPLOYMENT COMPLETED SUCCESSFULLY             ║"
        echo "╚═══════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "🎯 All Vault lifecycle phases completed via Salt states:"
        echo "   ✅ Phase 1: Package installation and environment setup"
        echo "   ✅ Phase 2: TLS certificate generation"
        echo "   ✅ Phase 3: Configuration file creation and validation"
        echo "   ✅ Phase 4: Service startup and health checks"
        echo "   ✅ Phase 5: Vault initialization with secure key storage"
        echo ""
        echo "🌐 Vault API: https://{{ grains.get('fqdn', 'localhost') }}:8179"
        echo "🔐 Initialization data: /var/lib/eos/secret/vault_init.json"
        echo "🔧 Management scripts: /usr/local/bin/eos-vault*"
        echo ""
        echo "🧂 Managed by Salt: All configuration changes should be made via Salt states"
        echo ""
    - require:
      - cmd: vault_init_summary