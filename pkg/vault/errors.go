// pkg/vault/errors.go - Structured error types with decision trees
// RATIONALE: Human-centric error messages guide users to solutions
//           instead of leaving them with "something failed, good luck"

package vault

import (
	"errors"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
)

// IsSecretNotFound checks if a Vault error is a "404 not found" style error.
func IsSecretNotFound(err error) bool {
	if err == nil {
		return false
	}
	// Vault often wraps 404 errors with strings like "no secret found at path" or HTTP 404 error text.
	msg := err.Error()
	return strings.Contains(msg, "no secret") ||
		strings.Contains(msg, "404") ||
		errors.Is(err, eos_err.ErrSecretNotFound)
}

// ErrPhasePrerequisiteMissing indicates a phase cannot run because
// a previous phase didn't complete properly or its artifacts were corrupted
type ErrPhasePrerequisiteMissing struct {
	Phase           string
	DependsOn       string
	MissingArtifact string
	DiagnosticCmd   string
	RecoveryCmd     string
}

func (e ErrPhasePrerequisiteMissing) Error() string {
	return fmt.Sprintf(`
═══════════════════════════════════════════════════════════
 Phase %s Failed: Prerequisite Missing
═══════════════════════════════════════════════════════════

This phase requires: %s
Missing artifact: %s

What happened:
  Phase %s did not complete successfully, OR
  its artifacts were corrupted/deleted after completion.

Recommended actions (in order):
  1. Check phase status:
     → %s

  2. Validate specific phase:
     → %s

  3. For fresh install (DESTRUCTIVE):
     → sudo eos create vault --clean

  4. For production systems:
     → sudo eos debug vault --full-report > vault-report.txt
     → Review vault-report.txt before taking action
     → Contact support if unsure

SECURITY: Do not run --clean on production without backup!

Technical Details:
  Missing: %s
  Required by: Phase %s
`, e.Phase, e.DependsOn, e.MissingArtifact, e.DependsOn, e.DiagnosticCmd, e.RecoveryCmd, e.MissingArtifact, e.Phase)
}

// ErrBootstrapPasswordInvalidStructure indicates the bootstrap password secret
// exists but has invalid structure or content
type ErrBootstrapPasswordInvalidStructure struct {
	Expected string
	Got      string
	Fields   []string
}

func (e ErrBootstrapPasswordInvalidStructure) Error() string {
	return fmt.Sprintf(`
Bootstrap password validation failed

Expected: %s
Got: %s
Available fields: %v

This indicates:
  • Phase 10a wrote the secret but with wrong structure
  • Vault storage backend corrupted the data
  • Secret was manually modified incorrectly

What this means:
  The bootstrap password secret exists in Vault, but it doesn't
  have the expected structure. This prevents MFA setup from
  reading the password correctly.

Recovery options:
  1. Automated fix (recommended):
     → sudo eos vault validate --phase 10a --fix

  2. Manual inspection:
     → vault kv get secret/eos/bootstrap
     → Check if 'password' field exists and is a string

  3. Full phase recovery:
     → sudo eos vault recover --phase 10a

Technical details:
  Path checked: secret/eos/bootstrap
  Expected structure: {password: string, created_at: timestamp, ...}
  Validation failure: %s
`, e.Expected, e.Got, e.Fields, e.Expected+" but got "+e.Got)
}
