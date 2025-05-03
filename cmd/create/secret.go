// cmd/create/secret.go

package create

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/spf13/cobra"
)

var (
	length int
	format string
)

var CreateSecretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Generate a secure random secret (like openssl rand -hex 32)",
	Example: `  eos create secret
  eos create secret --length 64
  eos create secret --length 24 --format base64`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		if length <= 0 {
			length = 32 // Default to openssl rand -hex 32
		}
		if format == "" {
			format = "hex"
		}

		buf := make([]byte, length)
		if _, err := rand.Read(buf); err != nil {
			return fmt.Errorf("failed to generate secure random bytes: %w", err)
		}

		switch format {
		case "hex":
			fmt.Println(hex.EncodeToString(buf))
		case "base64":
			fmt.Println(base64.StdEncoding.EncodeToString(buf))
		default:
			return errors.New("unsupported format: must be 'hex' or 'base64'")
		}
		return nil
	}),
}

func init() {
	CreateSecretCmd.Flags().IntVar(&length, "length", 0, "Length of random bytes to generate (default: 32)")
	CreateSecretCmd.Flags().StringVar(&format, "format", "", "Output format: hex (default) or base64")
}
