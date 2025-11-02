# API Client Framework - Usage Guide

*Last Updated: 2025-11-03*

## Quick Start

The API Client Framework provides a **declarative, YAML-driven** approach to adding API commands to Eos. Instead of writing 500+ lines of Cobra boilerplate, you write ~100 lines of YAML.

### Example: List Authentik Users

```bash
# Build Eos
go build -o eos ./cmd/

# List all users (table format - human-friendly)
sudo eos list authentik-api users

# Filter by type
sudo eos list authentik-api users --type=external

# Filter by status
sudo eos list authentik-api users --superuser --active

# Output as JSON (machine-readable)
sudo eos list authentik-api users --format=json

# Output as CSV (for spreadsheets)
sudo eos list authentik-api users --format=csv > users.csv
```

---

## Available Resources

### Authentik API Resources

| Resource | Description | Example Command |
|----------|-------------|-----------------|
| **users** | Authentik users | `eos list authentik-api users` |
| **groups** | Authentik groups | `eos list authentik-api groups` |
| **applications** | Authentik applications | `eos list authentik-api applications` |
| **providers** | Authentik proxy providers | `eos list authentik-api providers` |
| **brands** | Authentik brands | `eos list authentik-api brands` |

---

## Users Resource

### List Users

```bash
# List all users
sudo eos list authentik-api users

# Filter by user type
sudo eos list authentik-api users --type=internal
sudo eos list authentik-api users --type=external
sudo eos list authentik-api users --type=service_account

# Filter by status
sudo eos list authentik-api users --superuser
sudo eos list authentik-api users --active

# Filter by email or username
sudo eos list authentik-api users --email=alice@example.com
sudo eos list authentik-api users --username=alice

# Combine filters
sudo eos list authentik-api users --type=external --superuser --active
```

### Output Formats

```bash
# Table (default - human-friendly)
sudo eos list authentik-api users

# JSON (machine-readable, full structure)
sudo eos list authentik-api users --format=json

# YAML (human-readable, structured)
sudo eos list authentik-api users --format=yaml

# CSV (spreadsheet-compatible)
sudo eos list authentik-api users --format=csv > users.csv
```

---

## Groups Resource

### List Groups

```bash
# List all groups
sudo eos list authentik-api groups

# Filter groups by member UUID
sudo eos list authentik-api groups --member=123e4567-e89b-12d3-a456-426614174000

# Filter by group name
sudo eos list authentik-api groups --name="BionicGPT Users"

# Output as JSON
sudo eos list authentik-api groups --format=json
```

---

## Applications Resource

### List Applications

```bash
# List all applications
sudo eos list authentik-api applications

# Filter by application name
sudo eos list authentik-api applications --name=BionicGPT

# Filter by slug
sudo eos list authentik-api applications --slug=bionicgpt

# Output as table
sudo eos list authentik-api applications --format=table
```

---

## Providers Resource

### List Proxy Providers

```bash
# List all proxy providers
sudo eos list authentik-api providers

# Filter by provider name
sudo eos list authentik-api providers --name="BionicGPT Provider"

# Output as JSON
sudo eos list authentik-api providers --format=json
```

---

## Brands Resource

### List Brands

```bash
# List all brands
sudo eos list authentik-api brands

# Filter by domain
sudo eos list authentik-api brands --domain=bionicgpt.example.com

# Output as table
sudo eos list authentik-api brands --format=table
```

---

## Authentication

The framework discovers Authentik credentials automatically using this **priority order**:

### Priority 1: .env File (PRIMARY - next 6 months)

```bash
# Check credentials
cat /opt/hecate/.env | grep AUTHENTIK

# Should show:
# AUTHENTIK_URL=https://localhost
# AUTHENTIK_TOKEN=your-api-token-here
```

**This is the PRIMARY method** for the next 6 months during migration.

### Priority 2: Consul KV (preferred long-term)

```bash
# Store token in Consul KV (future)
consul kv put service/hecate/secrets/authentik_token "your-token"
consul kv put service/hecate/config/authentik_url "https://localhost"
```

### Priority 3: Vault (secure, rotatable)

```bash
# Store token in Vault (future)
vault kv put secret/hecate/authentik_token value="your-token"
```

### Priority 4: Environment Variable

```bash
# Set environment variables (runtime override)
export AUTHENTIK_URL="https://localhost"
export AUTHENTIK_TOKEN="your-token"
sudo -E eos list authentik-api users
```

### Priority 5: Interactive Prompt

If no credentials found, Eos will **prompt you interactively** (human-centric design).

---

## Output Format Examples

### Table Format (Default)

```
PK                                    USERNAME         EMAIL                    TYPE      ACTIVE
123e4567-e89b-12d3-a456-426614174000  alice_wonderland alice@example.com       external  true
234e5678-e89b-12d3-a456-426614174001  bob_builder      bob@example.com         external  true

Total: 2
```

**Features:**
- Aligned columns
- Truncates long values (max 50 chars)
- Shows row count

### JSON Format

```json
{
  "items": [
    {
      "pk": "123e4567-e89b-12d3-a456-426614174000",
      "username": "alice_wonderland",
      "email": "alice@example.com",
      "type": "external",
      "is_active": true
    }
  ],
  "total_count": 2
}
```

**Features:**
- Indented (human-readable)
- Full structure
- Machine-parseable

### YAML Format

```yaml
items:
  - pk: 123e4567-e89b-12d3-a456-426614174000
    username: alice_wonderland
    email: alice@example.com
    type: external
    is_active: true
total_count: 2
```

**Features:**
- Human-readable
- No quotes (cleaner than JSON)
- Pipeable

### CSV Format

```csv
pk,username,email,type,is_active
123e4567-e89b-12d3-a456-426614174000,alice_wonderland,alice@example.com,external,true
234e5678-e89b-12d3-a456-426614174001,bob_builder,bob@example.com,external,true
```

**Features:**
- Spreadsheet-compatible
- Import to Excel, Google Sheets
- Headers included

---

## Troubleshooting

### "Failed to initialize Authentik API client"

**Cause**: Credentials not found or invalid.

**Fix**:
1. Check `/opt/hecate/.env` has `AUTHENTIK_TOKEN` and `AUTHENTIK_URL`
2. Verify Authentik is running: `curl https://localhost/api/v3/`
3. Check token is valid: `curl -H "Authorization: Bearer $AUTHENTIK_TOKEN" https://localhost/api/v3/core/users/`
4. Run diagnostics: `sudo eos debug hecate`

### "Failed to list users: API returned status 403"

**Cause**: Token lacks permissions.

**Fix**:
1. Ensure token has read permissions for the resource
2. Check Authentik user permissions in UI
3. Generate new token with correct permissions

### "Unknown resource: xyz"

**Cause**: Resource not defined in `pkg/authentik/api_definition.yaml`.

**Fix**:
Check available resources:
```bash
sudo eos list authentik-api --help
```

Available resources: users, groups, applications, providers, brands

### "Filter validation failed"

**Cause**: Invalid filter value (e.g., wrong type).

**Fix**:
Check filter requirements in help:
```bash
sudo eos list authentik-api users --help
```

Example: `--type` must be one of: internal, external, service_account

---

## Advanced Usage

### Piping to jq (JSON processing)

```bash
# Get all external user emails
sudo eos list authentik-api users --type=external --format=json | \
  jq -r '.items[].email'

# Count superusers
sudo eos list authentik-api users --superuser --format=json | \
  jq '.total_count'

# Extract UUIDs
sudo eos list authentik-api users --format=json | \
  jq -r '.items[].pk'
```

### Piping to csvkit (CSV processing)

```bash
# Convert to Excel
sudo eos list authentik-api users --format=csv | \
  csvcut -c username,email,type > users.xlsx

# Filter CSV
sudo eos list authentik-api users --format=csv | \
  csvgrep -c type -m external > external_users.csv
```

### Combining with Other Commands

```bash
# List users and their groups
for user_pk in $(sudo eos list authentik-api users --format=json | jq -r '.items[].pk'); do
  echo "User: $user_pk"
  sudo eos list authentik-api groups --member="$user_pk" --format=table
done
```

---

## Next Steps

### Coming Soon (Phase 5-8)

**Phase 5: Read Command** - Get single resource by ID
```bash
# Will be available soon:
sudo eos read authentik-api user 123e4567-e89b-12d3-a456-426614174000
```

**Phase 6: Create/Update/Delete Commands**
```bash
# Will be available soon:
sudo eos create authentik-api user --username=alice --email=alice@example.com
sudo eos update authentik-api user {uuid} --type=internal
sudo eos delete authentik-api user {uuid}
```

**Phase 7: Additional Services**
- Wazuh API support
- Caddy API support
- Generic OpenAPI importer

---

## Reference

- **Implementation Plan**: [pkg/apiclient/README.md](README.md)
- **API Definition**: [pkg/authentik/api_definition.yaml](../authentik/api_definition.yaml)
- **Design Document**: [docs/API_CLIENT_FRAMEWORK_DESIGN.md](../../docs/API_CLIENT_FRAMEWORK_DESIGN.md)
- **CLAUDE.md**: Project standards and patterns

---

## Feedback

Found a bug or have a feature request? Open an issue on GitHub:
https://github.com/anthropics/claude-code/issues
