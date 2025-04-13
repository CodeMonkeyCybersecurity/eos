/* pkg/vault/ldap.go */

package vault

import "fmt"

func PrintNextSteps() {
	fmt.Println("\nNext Steps:")
	fmt.Println("🔐 Please configure multi-factor authentication (MFA) for your admin user using your organization's preferred method.")
	fmt.Println("📘 Refer to Vault's documentation for integrating MFA (e.g., via OIDC, LDAP, or a third-party MFA solution).")
	fmt.Println("\n✅ Vault secure setup completed successfully!")
}
