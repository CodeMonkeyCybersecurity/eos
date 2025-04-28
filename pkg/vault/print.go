package vault

import "fmt"

// PrintNextSteps prints the hint after Vault initialization.
func PrintNextSteps() {
	fmt.Println("")
	fmt.Println("🔔 Vault has been initialized, but is not yet unsealed.")
	fmt.Println("👉 Next steps:")
	fmt.Println("   1. Run: eos inspect vault-init   (to view and save your init keys)")
	fmt.Println("   2. Run: eos enable vault         (to unseal and fully enable Vault)")
	fmt.Println("")
}
