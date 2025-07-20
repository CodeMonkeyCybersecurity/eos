# Salt Random String Generator Documentation

*Last Updated: 2025-01-20*

## Overview

The `eos_random` Salt module provides cryptographically secure random string generation for use when HashiCorp Vault is not available in the environment. This module is automatically deployed as part of the Hecate bundle.

## Module Location

The module is deployed to: `/srv/salt/_modules/eos_random.py`

## Available Functions

### 1. `get_str(length=32, chars=None, prefix='')`
Generate a cryptographically secure random string.

**Usage in Salt States:**
```yaml
my_random_string:
  cmd.run:
    - name: echo "{{ salt['eos_random.get_str'](32) }}"
```

**Usage in Pillar:**
```yaml
secrets:
  api_key: {{ salt['eos_random.get_str'](64, prefix='key_') }}
```

### 2. `hex_str(length=64)`
Generate a random hexadecimal string.

**Example:**
```yaml
database_password: {{ salt['eos_random.hex_str'](32) }}
```

### 3. `password(length=16, include_special=True)`
Generate a secure password with complexity requirements.

**Example:**
```yaml
admin_password: {{ salt['eos_random.password'](20, include_special=True) }}
```

### 4. `api_key(prefix='eos_')`
Generate a base64-encoded API key.

**Example:**
```yaml
service_api_key: {{ salt['eos_random.api_key']('myapp_') }}
```

### 5. `uuid()`
Generate a random UUID.

**Example:**
```yaml
instance_id: {{ salt['eos_random.uuid']() }}
```

### 6. `get_or_create(key, length=32, chars=None, storage_path='/etc/eos/salt_secrets.json')`
Get an existing random value by key or create a new one. Provides persistence across Salt runs.

**Example:**
```yaml
# This will generate once and persist
persistent_secret: {{ salt['eos_random.get_or_create']('myapp_db_password', 32) }}
```

## Integration with Hecate

### Hybrid Secrets Management

Hecate uses a hybrid approach for secret management:

1. **With Vault**: Secrets are stored in Vault under the `hecate/` path
2. **Without Vault**: Secrets are generated using `eos_random` and stored locally

### Usage in Hecate States

```yaml
# In hecate/hybrid_secrets.sls
{% if salt['pillar.get']('hecate:vault_integration', True) %}
  # Use Vault for secrets
  {% set db_password = salt['vault.read']('hecate/database/password')['data']['value'] %}
{% else %}
  # Use eos_random for secrets
  {% set db_password = salt['eos_random.get_or_create']('hecate_db_password', 32) %}
{% endif %}
```

### Pillar Integration

```yaml
# In pillar/hecate/secrets.sls
hecate:
  secrets:
    jwt_secret: {{ salt['eos_random.get_or_create']('hecate_jwt_secret', 64) }}
    api_key: {{ salt['eos_random.get_or_create']('hecate_api_key', 32, prefix='hct_') }}
    oauth_secret: {{ salt['eos_random.get_or_create']('hecate_oauth_secret', 48) }}
```

## Security Considerations

1. **File Permissions**: The persistent secrets file (`/etc/eos/salt_secrets.json`) is automatically secured with 600 permissions
2. **Cryptographic Security**: Uses Python's `secrets` module for cryptographically strong randomness
3. **Persistence**: Secrets are only persisted when using `get_or_create()` function
4. **Rotation**: To rotate a secret, remove its key from the JSON file and re-run Salt

## Deployment

The module is automatically deployed when running the Hecate bundle:

```bash
salt-call state.apply hecate_bundle
```

This will:
1. Deploy the `eos_random.py` module
2. Sync Salt modules to make it available
3. Initialize the secrets storage file (if not using Vault)
4. Make the module available for all subsequent Salt runs

## Testing the Module

After deployment, test the module:

```bash
# Test random string generation
salt-call eos_random.get_str 32

# Test password generation
salt-call eos_random.password 16 include_special=True

# Test persistent secret
salt-call eos_random.get_or_create test_secret 32
```

## Troubleshooting

1. **Module not found**: Run `salt-call saltutil.sync_modules` to sync custom modules
2. **Permission denied**: Ensure `/etc/eos/` directory exists with proper permissions
3. **JSON decode error**: Check `/etc/eos/salt_secrets.json` for valid JSON format