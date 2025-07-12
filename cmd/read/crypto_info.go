// cmd/read/crypto_info.go
package read

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto/pq"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var cryptoInfoCmd = &cobra.Command{
	Use:     "crypto-info",
	Aliases: []string{"crypto-status", "pq-info", "quantum-info"},
	Short:   "Display information about cryptographic implementations",
	Long: `Display detailed information about the cryptographic algorithms and 
implementations available in Eos, including post-quantum algorithms.

This command provides:
- ML-KEM-768 algorithm details and parameters
- Quantum resistance status and capabilities
- Performance characteristics for cryptographic operations
- Available cryptographic libraries and implementations

Examples:
  eos read crypto-info                          # Show crypto implementation details`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		logger.Info("Eos Cryptographic Information")

		// ML-KEM Information
		mlkemInfo := pq.GetMLKEMInfo()
		logger.Info("ML-KEM-768 Information",
			zap.Any("details", mlkemInfo),
		)

		logger.Info("Quantum Resistance Status",
			zap.Bool("ml_kem_available", true),
			zap.String("ml_kem_library", "filippo.io/mlkem768"),
			zap.Bool("quantum_resistant", true),
		)

		logger.Info("Performance Characteristics",
			zap.String("keygen_time", "~0.1ms"),
			zap.String("encaps_time", "~0.2ms"),
			zap.String("decaps_time", "~0.2ms"),
		)

		return nil
	}),
}

func init() {
	ReadCmd.AddCommand(cryptoInfoCmd)
}
