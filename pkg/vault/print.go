package vault

import (
	"encoding/json"
	"fmt"
)

func PrintNextSteps() {
	fmt.Println("")
	fmt.Println("⚠️WARNING: You MUST securely back up the unseal keys and root token.")
	fmt.Println("WITHOUT THESE YOU CANNOT RECOVER YOUR VAULT.")

	fmt.Println("\n💾 These credentials have been saved to:")
	fmt.Println("")
	fmt.Println("/var/lib/eos/secret/vault_init.json")

	fmt.Println("\nTo view them, run either:")
	fmt.Println("    sudo cat /var/lib/eos/secret/vault_init.json")
	fmt.Println("")
	fmt.Println("    sudo eos read vault-init")
	fmt.Println("\n⚠️ Make sure no one is looking over your shoulder when you do this!")

	fmt.Println("\n➡️ NEXT STEPS:")
	fmt.Println("View and securely record the keys now. You will need them in the next step.")
	fmt.Println("Run:")
	fmt.Println("    sudo eos enable vault")

	fmt.Println("\nIMPORTANT: During enable, you will be asked to enter the root token and at least 3 of the unseal keys to complete the Vault setup.")

	fmt.Println("\n✅ Vault install complete — ready for enable phase.")
	fmt.Println("")
}

func PrintStorageSummary(primary string, primaryPath string, primaryResult string, fallback string, fallbackResult string) {
	fmt.Println()
	fmt.Println("🔒 Test Data Storage Summary")
	fmt.Printf("  %s: %s\n", primary, primaryResult)
	if primaryResult == "SUCCESS" {
		fmt.Printf("    📂 Path: %s\n", primaryPath)
	}
	if fallback != "N/A" {
		fmt.Printf("  %s: %s\n", fallback, fallbackResult)
		if fallbackResult == "SUCCESS" {
			fmt.Printf("    📂 Path: %s\n", diskFallbackPath())
		}
	}
	fmt.Println()
}

func PrintData(data map[string]interface{}, source, path string) {
	fmt.Println()
	fmt.Println("🔒 Test Data Contents:")
	raw, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(raw))
	fmt.Println()

	PrintInspectSummary(source, path)
}

func PrintInspectSummary(source, path string) {
	fmt.Println()
	fmt.Println("🔎 Test Data Inspection Summary")
	switch source {
	case "Vault":
		fmt.Printf("  🔐 Source: %s\n", source)
	case "Disk":
		fmt.Printf("  💾 Source: %s\n", source)
	default:
		fmt.Printf("  ❓ Source: %s\n", source)
	}
	fmt.Printf("  📂 Path: %s\n", path)
	fmt.Println()
}
