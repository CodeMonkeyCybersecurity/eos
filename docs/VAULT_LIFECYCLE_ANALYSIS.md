# Vault Lifecycle - Adversarial Analysis

*Last Updated: 2025-10-14*

## Executive Summary

This document provides a comprehensive adversarial analysis of the Eos Vault lifecycle from both user and business logic perspectives, identifying gaps, risks, and required improvements.

---

## Part 1: User Perspective Analysis

### Scenario 1: First-Time Vault User (Create New Cluster)

#### Current Flow:
1. Run `sudo eos create vault`
2. Prompted: "Join or Create?" → Choose Create
3. Vault installs, initializes with 5/3 Shamir keys
4. Keys saved to `/var/lib/eos/secret/vault_init.json` (0600)
5. User told: "Run `eos inspect vault-init` to retrieve keys"
6. Vault continues with EnableVault (auto-unseals, configures)

####  What Works:
- Keys are saved automatically
- File permissions are restrictive (0600)
- User is instructed how to retrieve keys
- SecurityWarnings displayed about key storage
- Vault is fully configured and operational

#### ❌ What's Broken/Missing:

**CRITICAL GAP #1: No Immediate Key Distribution**
- **Problem**: Keys are on disk on the SAME machine Vault is running on
- **Risk**: Single point of failure - if server is compromised or destroyed, keys are lost
- **User Question**: "How do I safely get these keys OFF this server?"
- **Missing**: Automated, secure key export/distribution mechanism

**CRITICAL GAP #2: No Key Separation Guidance**
- **Problem**: All 5 keys stored together violates Shamir's Secret Sharing model
- **Risk**: Defeats the purpose of key splitting
- **User Question**: "How do I split these keys to 5 different people?"
- **Missing**: Interactive key distribution workflow with verification

**CRITICAL GAP #3: No Backup Verification**
- **Problem**: No way to verify user has actually backed up keys
- **Risk**: User may proceed thinking keys are backed up when they're not
- **User Question**: "How do I know I've safely backed up my keys?"
- **Missing**: Mandatory backup confirmation with test unseal

**GAP #4: Root Token Security**
- **Problem**: Root token stored in same file as unseal keys
- **Risk**: Permanent superuser access alongside unlock keys
- **User Question**: "Should I revoke this root token after setup?"
- **Missing**: Automatic root token revocation after policy setup

**GAP #5: No Key Rotation Plan**
- **Problem**: No guidance on when/how to rotate unseal keys
- **Risk**: Keys may be compromised over time
- **User Question**: "How often should I rotate these keys?"
- **Missing**: Key rotation workflow and scheduling

---

### Scenario 2: Adding Second Node (Join Existing Cluster)

#### Current Flow:
1. Run `sudo eos create vault` on new server
2. Prompted: "Join or Create?" → Choose Join (default)
3. Prompted: "Leader API address?" → Enter `https://10.0.1.100:8200`
4. Vault installs, configures with retry_join
5. Service starts
6. **Phase 5.5**: Automatically joins cluster via SDK
7. User told: "Get 3 unseal keys from leader, run `vault operator unseal` 3 times"
8. EnableVault **SKIPPED** (gets config from cluster)

####  What Works:
- Prompts for join vs create
- Automatically joins cluster using SDK
- Correctly skips initialization
- Informs user to use leader's keys

#### ❌ What's Broken/Missing:

**CRITICAL GAP #6: No Automated Key Retrieval from Leader**
- **Problem**: User must manually get keys from leader node
- **Risk**: Insecure key transfer (email, chat, etc.)
- **User Question**: "How do I securely get the keys from the first node?"
- **Missing**: Secure, automated key transfer mechanism

**CRITICAL GAP #7: No Verification of Cluster Join Success**
- **Problem**: User not told if join actually succeeded
- **Risk**: Node may appear joined but not be in Raft peer list
- **User Question**: "How do I know the join actually worked?"
- **Missing**: Post-join verification showing peer list

**CRITICAL GAP #8: No Automated Unseal After Join**
- **Problem**: User must manually unseal with 3 keys
- **Risk**: Human error, especially at 3am during incident
- **User Question**: "Can't this be automated?"
- **Missing**: Option to fetch and use keys from secure storage

**GAP #9: No Leader Discovery**
- **Problem**: User must know exact leader IP address
- **Risk**: If leader IP changes, can't join
- **User Question**: "What if I don't know the leader address?"
- **Missing**: DNS-based or Consul-based leader discovery

**GAP #10: No Multi-Leader Join**
- **Problem**: Only prompts for ONE leader address
- **Risk**: If that one leader is down, join fails
- **User Question**: "What if the leader I specify is offline?"
- **Missing**: Ability to specify multiple retry_join nodes

---

### Scenario 3: Disaster Recovery - Server Lost

#### Current Flow:
None - no documented disaster recovery workflow

#### ❌ What's Completely Missing:

**CRITICAL GAP #11: No DR Documentation**
- **Problem**: No documented procedure for server failure
- **Risk**: Panic, data loss, incorrect recovery
- **User Question**: "My Vault server crashed, what do I do?"
- **Missing**: Step-by-step DR runbook

**CRITICAL GAP #12: No Automated Raft Snapshot Backups**
- **Problem**: No scheduled snapshots
- **Risk**: Data loss between backups
- **User Question**: "How do I backup Vault data?"
- **Missing**: Automated snapshot scheduling via cron/systemd

**CRITICAL GAP #13: No Snapshot Restore Workflow**
- **Problem**: `vault operator raft snapshot restore` exists but not integrated
- **Risk**: Users don't know how to restore
- **User Question**: "How do I restore from backup?"
- **Missing**: `eos restore vault --snapshot <path>` command

**CRITICAL GAP #14: No Cluster Quorum Monitoring**
- **Problem**: No alerting when cluster loses quorum
- **Risk**: Vault becomes unavailable without warning
- **User Question**: "How do I know if my cluster is healthy?"
- **Missing**: Health monitoring and alerting

---

## Part 2: Business Logic Analysis

### Key Retrieval & Distribution

#### Current State:
```go
// phase6a_init.go:105
func SaveInitResult(rc *eos_io.RuntimeContext, initRes *api.InitResponse) error {
    path := shared.VaultInitPath // /var/lib/eos/secret/vault_init.json
    // ... saves to disk with 0600 permissions
}
```

#### Problems:

**LOGIC GAP #1: Single Point of Storage**
- Keys stored only on Vault server itself
- Violates security best practice of off-server key storage
- **Fix Needed**: Add export options during initialization

**LOGIC GAP #2: No Key Splitting Workflow**
- All 5 keys saved to same file
- Defeats Shamir's Secret Sharing model
- **Fix Needed**: Interactive workflow to:
  1. Generate 5 individual key files
  2. Encrypt each with different passwords
  3. Prompt for delivery method (email, SCP, print QR codes)
  4. Confirm delivery to each key holder

**LOGIC GAP #3: No Secure Key Transport**
- User expected to manually transfer keys
- Opens vulnerability window
- **Fix Needed**: Built-in secure transport:
  - Age encryption with per-user public keys
  - Push to Vault on different server
  - SOPS integration
  - HashiCorp Boundary integration

---

### Cluster Operations

#### Current SDK Usage Audit:

 **Using SDK Properly:**
- `InitializeRaftCluster()` - uses `client.Sys().Init()`
- `JoinRaftCluster()` - uses `client.Sys().RaftJoin()`
- `UnsealVaultWithKeys()` - uses `client.Sys().Unseal()`

❌ **Still Shelling Out:**
```go
// cluster_operations.go:197 - GetRaftPeers
cmd := exec.CommandContext(rc.Ctx, "vault", "operator", "raft", "list-peers", "-format=json")

// cluster_operations.go:232 - ConfigureRaftAutopilot
cmd := exec.CommandContext(rc.Ctx, "vault", args...)

// cluster_operations.go:273 - GetAutopilotState
cmd := exec.CommandContext(rc.Ctx, "vault", "operator", "raft", "autopilot", "state", "-format=json")

// cluster_operations.go:329 - RemoveRaftPeer
cmd := exec.CommandContext(rc.Ctx, "vault", "operator", "raft", "remove-peer", nodeID)

// cluster_operations.go:352 - TakeRaftSnapshot
cmd := exec.CommandContext(rc.Ctx, "vault", "operator", "raft", "snapshot", "save", outputPath)

// cluster_operations.go:381 - RestoreRaftSnapshot
cmd := exec.CommandContext(rc.Ctx, "vault", args...)
```

**LOGIC GAP #4: Inconsistent API Usage**
- Core operations use SDK
- Management operations still shell out
- **Fix Needed**: Convert all to SDK

---

### Unseal Key Management for Joining Nodes

#### Current State:
```go
// cmd/create/secrets.go:308-313
logger.Info("terminal prompt: IMPORTANT: This node needs to be unsealed using the SAME unseal keys as the cluster leader.")
logger.Info("terminal prompt:   1. Obtain the 3 unseal keys from the cluster leader")
logger.Info("terminal prompt:   2. Run: vault operator unseal (3 times with different keys)")
```

#### Problems:

**LOGIC GAP #5: Manual Key Transfer Required**
- User must manually get keys from leader
- No automation or secure channel
- **Fix Needed**: Options to:
  1. Read keys from leader's `/var/lib/eos/secret/vault_init.json` via SSH
  2. Fetch from central key management system
  3. Use Vault's own secret storage (chicken/egg solved by ephemeral transit Vault)

**LOGIC GAP #6: No Automated Unseal After Join**
- User must manually run 3 unseal commands
- Error-prone, especially under pressure
- **Fix Needed**: `--auto-unseal-from-leader` flag that:
  1. Securely retrieves keys from leader
  2. Automatically unseals
  3. Verifies cluster membership
  4. Confirms in peer list

---

### Post-Installation Verification

#### Current State:
```go
// install.go:1075-1097 - verify() function
// Only checks:
// - Service is active
// - Vault responds to status command (exit code 0 or 2)
```

#### Problems:

**LOGIC GAP #7: Insufficient Verification for Clusters**
- No verification of Raft peer list
- No confirmation of cluster quorum
- No check of leader election
- **Fix Needed**: For cluster mode:
  ```go
  // Verify cluster membership
  peers, _ := client.Sys().RaftListPeers()
  // Verify this node is in peer list
  // Verify cluster has leader
  // Verify quorum is healthy
  ```

**LOGIC GAP #8: No Verification of Key Storage**
- No check that init file was actually saved
- No verification of file integrity
- **Fix Needed**:
  ```go
  // Verify init file exists and is readable
  // Compute checksum
  // Verify can deserialize keys
  // Confirm key count matches expected (5)
  ```

---

## Part 3: Required Fixes (Prioritized)

### P0 - Critical (Must Fix Immediately)

#### Fix #1: Automated Key Distribution Workflow
```go
// After initialization, prompt for key distribution
func DistributeInitKeys(rc *eos_io.RuntimeContext, initRes *api.InitResponse) error {
    logger := otelzap.Ctx(rc.Ctx)

    logger.Info("terminal prompt: ")
    logger.Info("terminal prompt: KEY DISTRIBUTION REQUIRED")
    logger.Info("terminal prompt: ======================= ")
    logger.Info("terminal prompt: ")
    logger.Info("terminal prompt: You have 5 unseal keys that must be distributed to 5 different key holders.")
    logger.Info("terminal prompt: This is CRITICAL for security - all keys in one place defeats Shamir's Secret Sharing.")
    logger.Info("terminal prompt: ")

    // Option 1: Generate individual encrypted key files
    logger.Info("terminal prompt: Option 1: Generate 5 encrypted key files (one per holder)")
    if PromptYesNo(rc, "Generate encrypted key files?", true) {
        return generateEncryptedKeyFiles(rc, initRes)
    }

    // Option 2: Display QR codes for manual transfer
    logger.Info("terminal prompt: Option 2: Display QR codes (scan with phone for offline storage)")
    if PromptYesNo(rc, "Display QR codes?", false) {
        return displayQRCodes(rc, initRes)
    }

    // Option 3: Export to external Vault
    logger.Info("terminal prompt: Option 3: Store in external Vault (requires existing Vault for key escrow)")
    if PromptYesNo(rc, "Export to external Vault?", false) {
        return exportToExternalVault(rc, initRes)
    }

    return nil
}

func generateEncryptedKeyFiles(rc *eos_io.RuntimeContext, initRes *api.InitResponse) error {
    logger := otelzap.Ctx(rc.Ctx)
    outputDir := "/var/lib/eos/vault-keys"

    if err := os.MkdirAll(outputDir, 0700); err != nil {
        return fmt.Errorf("create key directory: %w", err)
    }

    for i, key := range initRes.KeysB64 {
        // Prompt for password for this key holder
        logger.Info(fmt.Sprintf("terminal prompt: Key %d/%d - Enter password for key holder #%d:", i+1, len(initRes.KeysB64), i+1))
        password, err := eos_io.PromptPassword(rc, fmt.Sprintf("Password for holder %d", i+1))
        if err != nil {
            return fmt.Errorf("prompt password: %w", err)
        }

        // Encrypt key with password using age encryption
        encrypted, err := crypto.EncryptWithPassword([]byte(key), password)
        if err != nil {
            return fmt.Errorf("encrypt key %d: %w", i+1, err)
        }

        // Write encrypted key file
        filename := filepath.Join(outputDir, fmt.Sprintf("unseal-key-%d.age", i+1))
        if err := os.WriteFile(filename, encrypted, 0600); err != nil {
            return fmt.Errorf("write key file: %w", err)
        }

        logger.Info(fmt.Sprintf("terminal prompt: ✓ Key %d encrypted and saved to: %s", i+1, filename))
    }

    logger.Info("terminal prompt: ")
    logger.Info("terminal prompt: DISTRIBUTION INSTRUCTIONS:")
    logger.Info(fmt.Sprintf("terminal prompt: - Securely copy each file to its designated key holder"))
    logger.Info(fmt.Sprintf("terminal prompt: - Use SCP, encrypted USB, or other secure transport"))
    logger.Info(fmt.Sprintf("terminal prompt: - DELETE the files from this server after distribution"))
    logger.Info("terminal prompt: ")

    return nil
}
```

#### Fix #2: Convert Remaining Shell Commands to SDK
```go
// GetRaftPeers - convert to SDK
func GetRaftPeers(rc *eos_io.RuntimeContext) ([]RaftPeer, error) {
    log := otelzap.Ctx(rc.Ctx)
    log.Info("Retrieving Raft peer list via API")

    client, err := GetVaultClient(rc)
    if err != nil {
        return nil, fmt.Errorf("create vault client: %w", err)
    }

    // Use SDK to list peers
    // NOTE: Requires authenticated client with appropriate permissions
    secret, err := client.Logical().Read("sys/storage/raft/configuration")
    if err != nil {
        log.Error("Failed to read Raft configuration", zap.Error(err))
        return nil, fmt.Errorf("read raft config: %w", err)
    }

    // Parse peer information from response
    if secret == nil || secret.Data == nil {
        return nil, fmt.Errorf("no raft configuration found")
    }

    // Extract servers from config
    configData, ok := secret.Data["config"].(map[string]interface{})
    if !ok {
        return nil, fmt.Errorf("invalid config format")
    }

    serversData, ok := configData["servers"].([]interface{})
    if !ok {
        return nil, fmt.Errorf("invalid servers format")
    }

    var peers []RaftPeer
    for _, serverData := range serversData {
        server := serverData.(map[string]interface{})
        peer := RaftPeer{
            NodeID:  server["node_id"].(string),
            Address: server["address"].(string),
            Leader:  server["leader"].(bool),
            Voter:   server["voter"].(bool),
        }
        peers = append(peers, peer)
    }

    log.Info("Retrieved Raft peers via API", zap.Int("peer_count", len(peers)))
    return peers, nil
}

// TakeRaftSnapshot - convert to SDK
func TakeRaftSnapshot(rc *eos_io.RuntimeContext, token string, outputPath string) error {
    log := otelzap.Ctx(rc.Ctx)
    log.Info("Taking Raft snapshot via API", zap.String("output", outputPath))

    client, err := GetVaultClient(rc)
    if err != nil {
        return fmt.Errorf("create vault client: %w", err)
    }

    // Set token
    client.SetToken(token)

    // Take snapshot using SDK
    snapshot := client.Sys().RaftSnapshot()
    reader, err := snapshot.Read()
    if err != nil {
        log.Error("Failed to create snapshot", zap.Error(err))
        return fmt.Errorf("create snapshot: %w", err)
    }
    defer reader.Close()

    // Write snapshot to file
    outFile, err := os.Create(outputPath)
    if err != nil {
        return fmt.Errorf("create snapshot file: %w", err)
    }
    defer outFile.Close()

    if _, err := io.Copy(outFile, reader); err != nil {
        return fmt.Errorf("write snapshot: %w", err)
    }

    log.Info("Raft snapshot created successfully via API", zap.String("path", outputPath))
    return nil
}
```

#### Fix #3: Secure Key Retrieval for Joining Nodes
```go
// New function to securely retrieve keys from leader
func RetrieveKeysFromLeader(rc *eos_io.RuntimeContext, leaderAddr string, method string) ([]string, error) {
    logger := otelzap.Ctx(rc.Ctx)

    switch method {
    case "ssh":
        return retrieveKeysViaSSH(rc, leaderAddr)
    case "vault":
        return retrieveKeysFromVaultStorage(rc, leaderAddr)
    case "manual":
        return promptForManualKeys(rc)
    default:
        return nil, fmt.Errorf("unknown retrieval method: %s", method)
    }
}

func retrieveKeysViaSSH(rc *eos_io.RuntimeContext, leaderAddr string) ([]string, error) {
    logger := otelzap.Ctx(rc.Ctx)
    logger.Info("Retrieving unseal keys from leader via SSH", zap.String("leader", leaderAddr))

    // Prompt for SSH credentials
    logger.Info("terminal prompt: Enter SSH username for leader node:")
    username, err := eos_io.PromptInput(rc, "SSH username", "root")
    if err != nil {
        return nil, err
    }

    // Use SSH to cat the init file
    initPath := shared.VaultInitPath
    sshCmd := fmt.Sprintf("ssh %s@%s 'sudo cat %s'", username, leaderAddr, initPath)

    // Execute SSH command
    output, err := executeSecureCommand(rc, sshCmd)
    if err != nil {
        return nil, fmt.Errorf("ssh retrieve failed: %w", err)
    }

    // Parse init JSON
    var initRes api.InitResponse
    if err := json.Unmarshal([]byte(output), &initRes); err != nil {
        return nil, fmt.Errorf("parse init result: %w", err)
    }

    logger.Info("Successfully retrieved unseal keys from leader",
        zap.Int("key_count", len(initRes.KeysB64)))

    return initRes.KeysB64, nil
}

// Add to runCreateVaultNative after join:
if config.RaftMode == "join" && len(config.RetryJoinNodes) > 0 {
    // ... existing join code ...

    logger.Info("terminal prompt: ")
    logger.Info("terminal prompt: KEY RETRIEVAL OPTIONS")
    logger.Info("terminal prompt: =====================")
    logger.Info("terminal prompt: 1. Retrieve from leader via SSH (automated)")
    logger.Info("terminal prompt: 2. Enter keys manually")
    logger.Info("terminal prompt: 3. Skip unsealing (manual unseal later)")
    logger.Info("terminal prompt: ")

    choice, _ := eos_io.PromptInput(rc, "Select option [1-3]", "1")

    switch choice {
    case "1":
        keys, err := RetrieveKeysFromLeader(rc, config.RetryJoinNodes[0].APIAddr, "ssh")
        if err != nil {
            logger.Error("Failed to retrieve keys", zap.Error(err))
            return fmt.Errorf("key retrieval failed: %w", err)
        }

        // Automatically unseal with retrieved keys
        logger.Info("Unsealing with retrieved keys...")
        if err := vault.UnsealVaultWithKeys(rc, keys, 3); err != nil {
            return fmt.Errorf("unseal failed: %w", err)
        }
        logger.Info("✓ Node unsealed successfully")

    case "2":
        // Manual key entry
        keys, err := promptForManualKeys(rc)
        if err != nil {
            return err
        }
        if err := vault.UnsealVaultWithKeys(rc, keys, 3); err != nil {
            return fmt.Errorf("unseal failed: %w", err)
        }

    case "3":
        // Skip - user will unseal manually
        logger.Info("Skipping automatic unseal - run 'vault operator unseal' manually")
    }

    // Verify cluster membership
    logger.Info("Verifying cluster membership...")
    if err := verifyClusterMembership(rc); err != nil {
        logger.Warn("Could not verify cluster membership", zap.Error(err))
    }

    return nil
}
```

---

### P1 - Important (Fix Soon)

#### Fix #4: Post-Join Verification
```go
func verifyClusterMembership(rc *eos_io.RuntimeContext) error {
    logger := otelzap.Ctx(rc.Ctx)

    // Wait for Raft to stabilize
    time.Sleep(5 * time.Second)

    // Get peer list
    peers, err := GetRaftPeers(rc)
    if err != nil {
        return fmt.Errorf("get peers: %w", err)
    }

    // Get this node's ID
    hostname, _ := os.Hostname()

    // Check if this node is in peer list
    found := false
    var leaderID string
    for _, peer := range peers {
        if peer.NodeID == hostname {
            found = true
            logger.Info("✓ This node found in Raft peer list",
                zap.String("node_id", hostname),
                zap.Bool("voter", peer.Voter))
        }
        if peer.Leader {
            leaderID = peer.NodeID
        }
    }

    if !found {
        return fmt.Errorf("this node NOT found in Raft peer list")
    }

    if leaderID == "" {
        return fmt.Errorf("no leader elected in cluster")
    }

    logger.Info("✓ Cluster verification successful",
        zap.Int("total_peers", len(peers)),
        zap.String("leader", leaderID),
        zap.Bool("this_node_is_voter", found))

    // Display peer list
    logger.Info("terminal prompt: ")
    logger.Info("terminal prompt: CLUSTER PEERS:")
    for _, peer := range peers {
        status := "follower"
        if peer.Leader {
            status = "LEADER"
        }
        logger.Info(fmt.Sprintf("terminal prompt:   - %s: %s (%s)",
            peer.NodeID, status, peer.Address))
    }
    logger.Info("terminal prompt: ")

    return nil
}
```

#### Fix #5: Automated Snapshot Backups
```go
// Add systemd timer for automated snapshots
func ConfigureAutomatedSnapshots(rc *eos_io.RuntimeContext, schedule string) error {
    logger := otelzap.Ctx(rc.Ctx)
    logger.Info("Configuring automated Raft snapshots", zap.String("schedule", schedule))

    // Create snapshot script
    scriptPath := "/usr/local/bin/vault-snapshot.sh"
    script := `#!/bin/bash
# Automated Vault Raft snapshot script
# Generated by Eos

SNAPSHOT_DIR="/var/backups/vault"
SNAPSHOT_FILE="$SNAPSHOT_DIR/vault-snapshot-$(date +%Y%m%d-%H%M%S).snap"
RETENTION_DAYS=7

# Create snapshot directory
mkdir -p "$SNAPSHOT_DIR"

# Take snapshot
vault operator raft snapshot save "$SNAPSHOT_FILE"

# Cleanup old snapshots
find "$SNAPSHOT_DIR" -name "vault-snapshot-*.snap" -mtime +$RETENTION_DAYS -delete

# Log result
logger -t vault-snapshot "Snapshot created: $SNAPSHOT_FILE"
`

    if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
        return fmt.Errorf("write snapshot script: %w", err)
    }

    // Create systemd service
    servicePath := "/etc/systemd/system/vault-snapshot.service"
    service := `[Unit]
Description=Vault Raft Snapshot
After=vault.service
Requires=vault.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vault-snapshot.sh
User=vault
Environment="VAULT_ADDR=https://127.0.0.1:8200"
Environment="VAULT_SKIP_VERIFY=1"
`

    if err := os.WriteFile(servicePath, []byte(service), 0644); err != nil {
        return fmt.Errorf("write service file: %w", err)
    }

    // Create systemd timer
    timerPath := "/etc/systemd/system/vault-snapshot.timer"
    timer := fmt.Sprintf(`[Unit]
Description=Vault Raft Snapshot Timer
Requires=vault-snapshot.service

[Timer]
OnCalendar=%s
Persistent=true

[Install]
WantedBy=timers.target
`, schedule)

    if err := os.WriteFile(timerPath, []byte(timer), 0644); err != nil {
        return fmt.Errorf("write timer file: %w", err)
    }

    // Enable and start timer
    if err := systemdReload(rc); err != nil {
        return err
    }

    if err := systemdEnable(rc, "vault-snapshot.timer"); err != nil {
        return err
    }

    if err := systemdStart(rc, "vault-snapshot.timer"); err != nil {
        return err
    }

    logger.Info("✓ Automated snapshots configured",
        zap.String("schedule", schedule),
        zap.String("backup_dir", "/var/backups/vault"))

    return nil
}
```

---

## Part 4: Recommended Improvements

### Improvement #1: Multi-Leader Join Support
```go
// Update promptRaftClusterConfig to accept multiple leaders
func (vi *VaultInstaller) promptRaftClusterConfig() error {
    // ... existing code ...

    if vi.config.RaftMode == "join" {
        logger.Info("terminal prompt: How many leader addresses do you want to configure?")
        logger.Info("terminal prompt: (Recommended: 3+ for redundancy)")

        countStr, _ := eos_io.PromptInput(vi.rc, "Number of leaders [1-5]", "1")
        count, _ := strconv.Atoi(countStr)

        for i := 0; i < count; i++ {
            leaderAddr, err := eos_io.PromptInput(vi.rc,
                fmt.Sprintf("Leader %d API address", i+1), "")
            if err != nil || leaderAddr == "" {
                continue
            }

            vi.config.RetryJoinNodes = append(vi.config.RetryJoinNodes,
                shared.RetryJoinNode{
                    APIAddr: leaderAddr,
                })
        }
    }
}
```

### Improvement #2: Key Verification Test
```go
// Before completing setup, verify user can unseal with saved keys
func VerifyKeyBackup(rc *eos_io.RuntimeContext, initRes *api.InitResponse) error {
    logger := otelzap.Ctx(rc.Ctx)

    logger.Info("terminal prompt: ")
    logger.Info("terminal prompt: KEY BACKUP VERIFICATION")
    logger.Info("terminal prompt: =======================")
    logger.Info("terminal prompt: To ensure you have safely backed up your keys,")
    logger.Info("terminal prompt: please enter any 3 of the 5 unseal keys:")
    logger.Info("terminal prompt: ")

    var enteredKeys []string
    for i := 0; i < 3; i++ {
        key, err := eos_io.PromptInput(rc, fmt.Sprintf("Unseal key %d", i+1), "")
        if err != nil {
            return err
        }
        enteredKeys = append(enteredKeys, key)
    }

    // Verify at least 3 match
    matchCount := 0
    for _, entered := range enteredKeys {
        for _, actual := range initRes.KeysB64 {
            if entered == actual {
                matchCount++
                break
            }
        }
    }

    if matchCount < 3 {
        logger.Error("Key verification failed - keys do not match")
        return fmt.Errorf("key verification failed")
    }

    logger.Info("✓ Key verification successful - you have the correct keys backed up")
    return nil
}
```

---

## Summary

### Critical Gaps Identified: 14
- **P0 (Immediate)**: 3
  - Key distribution workflow
  - Convert shell commands to SDK
  - Secure key retrieval for joining nodes

- **P1 (Important)**: 2
  - Post-join verification
  - Automated snapshot backups

- **P2 (Recommended)**: 9
  - Multi-leader join support
  - Key verification test
  - DR documentation
  - Snapshot restore workflow
  - Cluster monitoring
  - Root token auto-revocation
  - Key rotation workflow
  - Leader discovery
  - Quorum monitoring

### SDK/API Usage Status:
 **Using SDK**: 5 functions
❌ **Still Shelling Out**: 6 functions

### User Experience Gaps:
- No automated key distribution
- No secure key transfer between nodes
- No backup verification
- No disaster recovery workflow
- Manual unseal required for joining nodes

### Security Improvements Needed:
- Enforce key separation (Shamir model)
- Automate root token revocation
- Add key rotation capability
- Implement backup verification
- Add cluster health monitoring
