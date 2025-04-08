/* pkg/interaction/crypto.go */

package interaction

import (
	"bufio"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
)

func ConfirmHashedInputs(reader *bufio.Reader, keyLabel string, count int, tokenLabel string, expectedHashes []string, expectedTokenHash string) error {
	for {
		fmt.Printf("Please re-enter %d unique keys and the token to confirm.\n", count)

		keys, err := readLines(reader, keyLabel, count)
		if err != nil {
			fmt.Println("❌ Error reading keys:", err)
			continue
		}

		token, err := readLine(reader, tokenLabel)
		if err != nil {
			fmt.Println("❌ Error reading token:", err)
			continue
		}

		if !crypto.AllUnique(keys) {
			fmt.Println("⚠️ Keys must be unique. Try again.")
			continue
		}

		if !crypto.AllHashesPresent(crypto.HashStrings(keys), expectedHashes) || crypto.HashString(token) != expectedTokenHash {
			fmt.Println("❌ One or more values are incorrect. Try again.")
			continue
		}

		fmt.Println("✅ Confirmation successful.")
		return nil
	}
}
