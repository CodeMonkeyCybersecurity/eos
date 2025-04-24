/*

## 7. Unseal Vault

- `TryLoadUnsealKeysFromFallback() ([]string, error)` ✅
- `PromptUnsealKeys() ([]string, error)`
- `SubmitUnsealKeys(...)`
- `func ValidateVaultInitFile(path string) error`

### Decision: Vault Unseal Strategy (Initial)

- EOS will unseal Vault via an **interactive CLI prompt** for 3 of 5 base64-encoded unseal keys.
- The root token must also be manually entered and validated with the Vault API.
- EOS offers to save init data (`vault-init.json`) to:
  - Vault KV path (`secret/init/vault-init`)
  - Or local fallback (`/var/lib/eos/secrets/vault-init.json`)
- `--dev-mode` enables fallback unseal automatically
- EOS will validate the integrity and completeness of `vault-init.json` on each use.
- The file is expected to contain exactly 5 base64 unseal keys and a root token; malformed files will trigger a recovery prompt.

#### ⚠️ Two-Stage Confirmation
1. Prompt to re-enter all keys to verify they were saved
2. Confirm irreversible deletion if fallback not chosen

- All input is hidden and validated for format
- Root token is also validated during this step

✅ Default flow for secure interactive operator setup.
- ⚠️ If fallback is not chosen, EOS will perform a **two-stage confirmation** before discarding unseal materials:

  1. **Re-entry Verification Prompt:**
     ```plaintext
     ✅ Confirm: Please confirm you have saved the unseal keys and root token securely by entering them here:
     [Prompt for unseal keys 1-3 and root token again]
     ```
     EOS checks these values match the originals.

  2. **Final Deletion Consent Prompt:**
     ```plaintext
     ✅ Confirm: You have saved the unseal keys and root token securely, so we will now delete these keys from disk.
     Please confirm you understand that if you lose these keys, you will not be able to recover Vault should something go wrong. [y/N]?
     ```

- Only after both confirmations will EOS wipe unseal materials from memory and avoid writing any to disk.

- During development, a `--dev-mode` flag enables always-writing `vault-init.json` to disk with a warning.

- This unseal flow is used:
  - On first-time Vault install/init
  - On any future startup where Vault is sealed and cannot be auto-unsealed via Vault Agent

- All unseal key prompts will include base64-format reminders and hide input for security.

### Decision: Vault Runtime Unseal Strategy

- EOS will check if Vault is sealed before performing any secure CLI operations (e.g., reading secrets, syncing LDAP).
- If Vault is sealed at runtime, the following logic applies:

#### 🟢 Tier 1: Fallback Unseal (Disk-based vault-init.json)
- If fallback is enabled (explicitly or via `--dev-mode`), EOS will:
  - Load `/var/lib/eos/secrets/vault-init.json`
  - Attempt to extract unseal keys and submit them via API
  - If successful, Vault becomes unsealed automatically
  - This is the **default fallback in development**

- EOS will check the existence, ownership, and format of `vault-init.json` before using it.
- If it exists but is invalid, EOS will log a warning and fallback to manual recovery.

✅ *Recommended for short-term development and test environments.*

---

#### 🔵 Tier 2: Manual Recovery via `eos unseal vault`
- If fallback fails or is not enabled:
  - EOS aborts with a clear error message
  - The user is instructed to run:
    ```sh
    eos unseal vault
    ```
  - This command will:
    - Prompt for 3-of-5 unseal keys
    - Confirm re-entry if configured
    - Offer fallback again if available but previously skipped

✅ *Always available, CLI operator fallback path.*

---

#### 🟣 Tier 3: Vault Agent + Auto-Unseal via Transit Seal
- EOS will eventually support auto-unseal using Vault’s `transit` seal method:
  - A separate "unsealer Vault" (Vault #1) will hold the transit key
  - This unsealer Vault will be initialized and unsealed via normal EOS flows
  - The main Vault (Vault #2) will use:
    ```hcl
    seal "transit" {
      address    = "https://127.0.0.1:9179"
      token      = "..."
      key_name   = "vault-unseal-key"
    }
    ```

✅ *This will be the long-term secure and scalable strategy.*

- This strategy **avoids storing unseal keys permanently in memory or disk**, except when the user has explicitly enabled fallback (e.g. in development).
- Production setups should transition to **auto-unseal using Vault Agent and a secure backend**.

- Runtime sealing is treated as an eos action action, which it is explicity configured to resolve silently, providing certain safeguards are in plcae.

- any modification of the vault not strictly needed by background system processes will require authenticating as a local sudoer who has the permissions to access the vault and make these changes.

### Flag Behavior: `--dev-mode`

- When passed to `eos create vault` or related commands, `--dev-mode` will:
  - Automatically enable writing `/var/lib/eos/secrets/vault-init.json` on init
  - Automatically enable fallback-based unsealing at runtime
  - Relax certain hardening checks (e.g., cert verification)
  - Emit a warning that this mode is for local development only

✅ This ensures that fallback-based Vault unseal is enabled with zero config in development.

### Decision: Vault Transit Auto-Unseal (Planned Long-Term Strategy)

EOS will support a secure auto-unseal mechanism using Vault’s built-in `transit` seal functionality.

This requires two Vault instances:

#### 🔐 Vault #1: Unsealer Vault
- Acts as a **secure transit key provider**
- Initialized and unsealed once via normal `eos create vault`
- Transit engine is enabled at `transit/`
- A key (e.g. `vault-unseal-key`) is created for sealing operations
- Policy and token/AppRole are created with permission to encrypt/decrypt via `transit/vault-unseal-key`

#### 📦 Vault #2: Sealed Vault (e.g., production Vault)
- Uses the following configuration in `vault.hcl`:
```
  hcl
  seal "transit" {
    address    = "https://127.0.0.1:9179"
    token      = "..."
    key_name   = "vault-unseal-key"
  }
```
To simplify setup, EOS will provide a command:

eos bootstrap vault-unsealer --primary

This command:
	•	Installs and configures Vault #1 (unsealer)
	•	Enables transit/
	•	Creates the key and policy
	•	Outputs the seal configuration block for use by Vault #2
	•	Stores credentials in Vault Agent-compatible form if --dev-mode is passed

✅ This approach supports long-term automation while preserving secure defaults.

⸻

Future Planning: High Availability (HA) Considerations
	•	EOS will scaffold placeholders for HA lifecycle support in:
	•	pkg/vault/ha.go
	•	eos join vault-cluster, eos promote vault, etc.
	•	Full HA logic is not implemented yet, but paths will be pre-defined so later support is drop-in compatible.

✅ HA readiness is treated as a “design affordance” — invisible until needed, but architecturally sound.

---

## 8. Validate Root Token

- `PromptRootToken() (string, error)`
- `ValidateRootToken(client *api.Client, token string) error`

---

## 13. Wait for Vault Agent Token

- `WaitForAgentToken(path string) error`
- `ValidateAgentToken(client *api.Client, token string) error`
- `SetVaultToken(token string) error`  // Configures Vault client to use the agent token

---

*/