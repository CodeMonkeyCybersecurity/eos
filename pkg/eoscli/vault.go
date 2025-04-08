// pkg/eoscli/vault.go
package eoscli

import (
	"fmt"
	"os/exec"
	"strings"
)

// enableVaultAuthMethods enables both AppRole and userpass for "eos".
func enableVaultAuthMethods(password string) error {
	fmt.Println("🔐 Enabling Vault auth methods: userpass and approle")

	if err := enableAuthMethod("userpass", "userpass"); err != nil {
		return err
	}
	if err := enableAuthMethod("approle", "approle"); err != nil {
		return err
	}

	if err := createUserpassAccount(password); err != nil {
		return err
	}
	if err := createAppRole(); err != nil {
		return err
	}

	fmt.Println("✅ Vault auth methods for eos configured")
	return nil
}

func enableAuthMethod(path, method string) error {
	cmd := exec.Command("vault", "auth", "enable", "-path="+path, method)
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "path is already in use") {
		return fmt.Errorf("failed to enable %s auth: %v\n%s", method, err, out)
	}
	return nil
}

func createUserpassAccount(password string) error {
	fmt.Println("👤 Creating eos userpass account...")
	cmd := exec.Command("vault", "write",
		"auth/userpass/users/eos",
		"policies=admin-full",
		fmt.Sprintf("password=%s", password),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to write eos userpass: %v\n%s", err, out)
	}
	return nil
}

func createAppRole() error {
	fmt.Println("🔐 Creating eos AppRole...")
	cmd := exec.Command("vault", "write",
		"auth/approle/role/eos",
		"policies=admin-full",
		"secret_id_ttl=0",
		"token_ttl=1h",
		"token_max_ttl=4h",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create eos AppRole: %v\n%s", err, out)
	}
	return nil
}
