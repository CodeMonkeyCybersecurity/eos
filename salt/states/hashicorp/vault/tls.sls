# Vault TLS Certificate Generation
# Replicates functionality from phase3_tls_cert.go

{% set vault = pillar.get('vault', {}) %}
{% set vault_user = vault.get('user', 'vault') %}
{% set vault_group = vault.get('group', 'vault') %}
{% set tls_path = vault.get('tls_path', '/opt/vault/tls') %}
{% set hostname = grains.get('fqdn', grains.get('id', 'localhost')) %}

# Ensure TLS directory exists
vault_tls_directory:
  file.directory:
    - name: {{ tls_path }}
    - user: {{ vault_user }}
    - group: {{ vault_group }}
    - mode: 750
    - makedirs: True

# Generate private key (replicating OpenSSL commands from phase3_tls_cert.go)
vault_tls_private_key:
  cmd.run:
    - name: openssl genrsa -out {{ tls_path }}/tls.key 2048
    - creates: {{ tls_path }}/tls.key
    - require:
      - file: vault_tls_directory
  file.managed:
    - name: {{ tls_path }}/tls.key
    - user: {{ vault_user }}
    - group: {{ vault_group }}
    - mode: 644
    - require:
      - cmd: vault_tls_private_key

# Create OpenSSL config for certificate with SANs (replicating SAN logic from Go code)
vault_openssl_config:
  file.managed:
    - name: {{ tls_path }}/openssl.conf
    - contents: |
        [req]
        default_bits = 2048
        prompt = no
        distinguished_name = req_distinguished_name
        req_extensions = v3_req

        [req_distinguished_name]
        C=AU
        ST=NSW
        L=Sydney
        O=CodeMonkey
        OU=Eos
        CN={{ hostname }}

        [v3_req]
        basicConstraints = CA:FALSE
        keyUsage = nonRepudiation, digitalSignature, keyEncipherment
        subjectAltName = @alt_names

        [alt_names]
        DNS.1 = {{ hostname }}
        DNS.2 = localhost
        DNS.3 = vhost1
        IP.1 = 127.0.0.1
        IP.2 = ::1
    - user: {{ vault_user }}
    - group: {{ vault_group }}
    - mode: 644
    - require:
      - file: vault_tls_directory

# Generate self-signed certificate with SANs
vault_tls_certificate:
  cmd.run:
    - name: openssl req -new -x509 -key {{ tls_path }}/tls.key -out {{ tls_path }}/tls.crt -days 365 -config {{ tls_path }}/openssl.conf -extensions v3_req
    - creates: {{ tls_path }}/tls.crt
    - require:
      - cmd: vault_tls_private_key
      - file: vault_openssl_config
  file.managed:
    - name: {{ tls_path }}/tls.crt
    - user: {{ vault_user }}
    - group: {{ vault_group }}
    - mode: 644
    - require:
      - cmd: vault_tls_certificate

# Copy certificate for Vault Agent (replicating ca.crt creation from Go code)
vault_ca_cert_copy:
  file.copy:
    - name: /etc/vault.d/ca.crt
    - source: {{ tls_path }}/tls.crt
    - user: {{ vault_user }}
    - group: {{ vault_group }}
    - mode: 644
    - require:
      - file: vault_tls_certificate

# Install certificate in system CA trust store (Debian/Ubuntu)
{% if grains['os_family'] == 'Debian' %}
vault_system_ca_trust:
  file.copy:
    - name: /usr/local/share/ca-certificates/vault-local-ca.crt
    - source: {{ tls_path }}/tls.crt
    - mode: 644
    - require:
      - file: vault_tls_certificate
  cmd.run:
    - name: update-ca-certificates
    - require:
      - file: vault_system_ca_trust
{% endif %}

# Install certificate in system CA trust store (RHEL/CentOS)
{% if grains['os_family'] == 'RedHat' %}
vault_system_ca_trust:
  file.copy:
    - name: /etc/pki/ca-trust/source/anchors/vault-local-ca.crt
    - source: {{ tls_path }}/tls.crt
    - mode: 644
    - require:
      - file: vault_tls_certificate
  cmd.run:
    - name: update-ca-trust extract
    - require:
      - file: vault_system_ca_trust
{% endif %}

# Clean up temporary OpenSSL config
vault_cleanup_openssl_config:
  file.absent:
    - name: {{ tls_path }}/openssl.conf
    - require:
      - cmd: vault_tls_certificate