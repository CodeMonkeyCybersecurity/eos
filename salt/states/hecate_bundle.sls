# Hecate Bundle State
# This state bundles all required dependencies for Hecate deployment
# It ensures all prerequisites are installed before Hecate deployment begins
# Includes proper random string generation when Vault is not available

include:
  - hashicorp.consul
  - hashicorp.nomad
  - hashicorp.vault
  - docker
  - hecate.hybrid_secrets
  - hecate

# Ensure proper ordering
hecate_prerequisites:
  test.succeed_with_changes:
    - name: "Hecate prerequisites installed"
    - require:
      - sls: hashicorp.consul
      - sls: hashicorp.nomad
      - sls: hashicorp.vault
      - sls: docker
    - require_in:
      - sls: hecate

# Configure Consul for Hecate
consul_configure_for_hecate:
  cmd.run:
    - name: |
        # Wait for Consul to be ready
        for i in {1..30}; do
          if consul members >/dev/null 2>&1; then
            break
          fi
          sleep 2
        done
        
        # Create Hecate namespace in Consul
        consul namespace create -name=hecate 2>/dev/null || true
    - require:
      - sls: hashicorp.consul
    - require_in:
      - sls: hecate

# Configure Nomad for Hecate
nomad_configure_for_hecate:
  cmd.run:
    - name: |
        # Wait for Nomad to be ready
        for i in {1..30}; do
          if nomad status >/dev/null 2>&1; then
            break
          fi
          sleep 2
        done
        
        # Create Hecate namespace in Nomad
        nomad namespace apply -description "Hecate services" hecate 2>/dev/null || true
    - require:
      - sls: hashicorp.nomad
    - require_in:
      - sls: hecate

# Configure Vault for Hecate (if enabled)
{% if salt['pillar.get']('hecate:vault_integration', True) %}
vault_configure_for_hecate:
  cmd.run:
    - name: |
        # Wait for Vault to be ready
        export VAULT_ADDR=http://127.0.0.1:8200
        for i in {1..30}; do
          if vault status >/dev/null 2>&1; then
            break
          fi
          sleep 2
        done
        
        # Enable KV v2 secrets engine for Hecate
        vault secrets enable -path=hecate kv-v2 2>/dev/null || true
        
        # Create policy for Hecate
        vault policy write hecate - <<EOF
        path "hecate/*" {
          capabilities = ["create", "read", "update", "delete", "list"]
        }
        EOF
    - env:
      - VAULT_ADDR: http://127.0.0.1:8200
    - require:
      - sls: hashicorp.vault
    - require_in:
      - sls: hecate
{% endif %}

# Ensure Docker is configured
docker_configure_for_hecate:
  cmd.run:
    - name: |
        # Create Docker network for Hecate if it doesn't exist
        docker network create hecate-network 2>/dev/null || true
        
        # Ensure Docker is running
        systemctl is-active docker || systemctl start docker
    - require:
      - sls: docker
    - require_in:
      - sls: hecate

# Ensure custom Salt modules directory exists
ensure_salt_modules_dir:
  file.directory:
    - name: /srv/salt/_modules
    - makedirs: True
    - mode: 755

# Deploy custom Salt modules for random string generation
deploy_eos_random_module:
  file.managed:
    - name: /srv/salt/_modules/eos_random.py
    - source: salt://_modules/eos_random.py
    - makedirs: True
    - mode: 644
    - require:
      - file: ensure_salt_modules_dir
    - require_in:
      - cmd: sync_eos_modules

# Sync custom modules to make them available
sync_eos_modules:
  cmd.run:
    - name: salt-call --local saltutil.sync_modules
    - require:
      - file: deploy_eos_random_module
    - require_in:
      - sls: hecate.hybrid_secrets
      - sls: hecate

# Create Hecate directories
hecate_directories:
  file.directory:
    - names:
      - /opt/hecate
      - /opt/hecate/config
      - /opt/hecate/nomad
      - /opt/hecate/nomad/jobs
      - /var/lib/hecate
      - /var/lib/hecate/terraform
      - /var/log/hecate
      - /etc/eos  # For salt_secrets.json storage
    - user: root
    - group: root
    - mode: 755
    - makedirs: True
    - require_in:
      - sls: hecate

# Initialize secrets storage if not using Vault
{% if not salt['pillar.get']('hecate:vault_integration', True) %}
initialize_salt_secrets:
  file.managed:
    - name: /etc/eos/salt_secrets.json
    - mode: 600
    - user: root
    - group: root
    - replace: False
    - contents: '{}'
    - require:
      - file: hecate_directories
    - require_in:
      - sls: hecate.hybrid_secrets
{% endif %}

# Set grains to indicate Hecate node
hecate_grains:
  grains.present:
    - name: roles
    - value:
      - hecate
    - require_in:
      - sls: hecate