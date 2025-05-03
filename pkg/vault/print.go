package vault

import "fmt"

func PrintNextSteps() {
	fmt.Println("⚠️WARNING: You MUST securely back up the unseal keys and root token.")
	fmt.Println("WITHOUT THESE YOU CANNOT RECOVER YOUR VAULT.")

	fmt.Println("\n💾 These credentials have been saved to:")
	fmt.Println("/var/lib/eos/secret/vault_init.json")

	fmt.Println("\nTo view them, run either:")
	fmt.Println("- sudo cat /var/lib/eos/secret/vault_init.json")
	fmt.Println("- eos inspect vault-init")
	fmt.Println("⚠️ Make sure no one is looking over your shoulder when you do this!")

	fmt.Println("\n ➡️ NEXT STEPS:")
	fmt.Println("1️⃣  View and securely record the keys now. You will need them in the next step.")
	fmt.Println("2️⃣  Run:")
	fmt.Println("sudo eos enable vault")

	fmt.Println("\nIMPORTANT: During enable, you will be asked to enter the root token and at least 3 of the unseal keys to complete the Vault setup.")

	fmt.Println("\n✅ Vault install complete — ready for enable phase.")
}
