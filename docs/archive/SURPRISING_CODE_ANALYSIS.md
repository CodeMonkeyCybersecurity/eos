# Code Analysis: Patterns Likely to Generate Surprising Results

## Critical Issues Found

### 🚨 Security Vulnerabilities

1. **Hardcoded Default Credentials** (`pkg/eos_postgres/postgres.go:36-37`)
   ```go
   dsn = "host=localhost user=postgres password=postgres " +
       "dbname=eos_kvm port=5432 sslmode=disable"
   ```
   - **Risk**: Falls back to weak password `postgres` and disables SSL
   - **Impact**: Production database could be compromised

2. **Incomplete Security Sanitization** (`pkg/shared/api_input_fuzz_test.go:418-425`)
   ```go
   func sanitizeJSONInput(jsonData string) string {
       // TODO: Implement JSON input sanitization
       return strings.ReplaceAll(jsonData, "<script>", "")
   }
   ```
   - **Risk**: Trivial bypass of XSS protection
   - **Impact**: Security vulnerabilities in production

### ️ Network Timeout Issues

3. **Indefinite Network Hangs** (`pkg/vault/phase8_health_check.go:104`)
   ```go
   resp, err := http.Get(url)  // No timeout!
   ```
   - **Risk**: Process can hang indefinitely on unresponsive Vault
   - **Impact**: System becomes unresponsive, requires manual intervention

4. **Download Hangs** (`pkg/utils/download.go:22`)
   ```go
   resp, err := http.Get(url)  // No timeout!
   ```
   - **Risk**: File downloads can hang on slow/unresponsive servers
   - **Impact**: Installation/update processes stall

### 🏃‍♂️ Race Conditions

5. **Global State Race** (`pkg/xdg/credentials.go:19`)
   ```go
   var globalCredentialStore CredentialStore  // No synchronization!
   ```
   - **Risk**: Concurrent access without mutex protection
   - **Impact**: Credential operations could corrupt or fail unpredictably

6. **TOCTOU File Race** (`pkg/eos_unix/ssh.go:56-67`)
   ```go
   f, err := os.OpenFile(configPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
   // ...later...
   data, err := os.ReadFile(configPath)  // File could change between operations!
   ```
   - **Risk**: SSH config could be corrupted by concurrent access
   - **Impact**: SSH access could break unexpectedly

### 🤫 Silent Failures

7. **Ignored Critical Errors** (`pkg/storage_monitor/contention.go:38`)
   ```go
   metrics, _ = detectContentionWithIostat(rc)  // Error silently ignored!
   ```
   - **Risk**: Storage monitoring failures are hidden
   - **Impact**: Performance issues go undetected

8. **Parse Errors Ignored** (`pkg/eos_unix/ps.go:171,187`)
   ```go
   memUsage, _ = strconv.ParseFloat(fields[1], 64)  // Parse errors ignored!
   totalMem, _ = strconv.ParseFloat(fields[1], 64)
   ```
   - **Risk**: Memory calculations use zero values on parse failure
   - **Impact**: Incorrect system monitoring metrics

### 🎭 Misleading Function Behavior

9. **Hostname Function Lies** (`pkg/eos_unix/check.go:76-80`)
   ```go
   func GetHostname() string {
       hostname, err := os.Hostname()
       if err != nil {
           return "localhost"  // Lies about the actual hostname!
       }
       return hostname
   }
   ```
   - **Risk**: Function returns fake hostname instead of error
   - **Impact**: Network configuration using wrong hostname

###  Hardcoded Paths

10. **Hardcoded System Paths** (`pkg/exportutil/outpath.go:13`)
    ```go
    func EnsureDir() error { return os.MkdirAll("/opt/exports", 0o700) }
    ```
    - **Risk**: Path may not exist or be writable on all systems
    - **Impact**: Export functionality fails on non-standard systems

## Recommendations by Priority

### 🚨 IMMEDIATE (Security Critical)
1. **Remove hardcoded credentials** - require explicit database configuration
2. **Complete security sanitization** - implement proper input validation
3. **Add synchronization** to global credential store

### ⚡ HIGH (Reliability Critical)  
4. **Add timeouts** to all HTTP operations using `context.WithTimeout()`
5. **Fix TOCTOU race** in SSH config handling with proper file locking
6. **Handle all errors explicitly** - never use `_` to ignore errors

### 📊 MEDIUM (User Experience)
7. **Make paths configurable** instead of hardcoding system directories
8. **Return errors** from functions that can fail instead of fake defaults
9. **Add prominent logging** when falling back to alternative implementations

###  LOW (Code Quality)
10. **Document unexpected behavior** in function comments
11. **Add configuration options** for network binding instead of localhost defaults

## Impact Assessment

- **Security Risk**: HIGH (hardcoded credentials, incomplete sanitization)
- **Reliability Risk**: HIGH (network hangs, race conditions)  
- **User Surprise Factor**: HIGH (silent failures, misleading functions)
- **Debugging Difficulty**: HIGH (errors hidden, fake return values)

These patterns represent the most likely sources of surprising behavior that could affect users in production environments.