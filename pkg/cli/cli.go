// pkg/cli/cli.go
//
// # EOS CLI User Experience Abstraction System
//
// This package implements the abstracted user experience for EOS, where users
// interact with a consistent `eos create X` interface regardless of the underlying
// orchestration technology ( for infrastructure, Nomad for applications).
//
// # User Experience Abstraction Implementation
//
// ## Transparent Dual-Layer Deployment
//
// Users never need to understand or manage the underlying complexity:
//
// ```bash
// # User sees this simple interface
// eos create grafana --admin-password secret123
//
// # Behind the scenes:
// # 1. Determines this is an application service (not infrastructure)
// # 2. Ensures Nomad is running (auto-installs if needed)
// # 3. Generates Nomad job from template
// # 4. Deploys via Nomad with service discovery
// # 5. Reports success with access URLs
// ```
//
// ## Service Classification (Transparent to Users)
//
// The system automatically determines the deployment method:
//
// **Application Services** (Nomad):
// - grafana, jenkins, mattermost, n8n, vault
// - Containerized applications with service discovery
// - Automatic scaling and health monitoring
// - Integrated with Hecate reverse proxy
//
// **Infrastructure Services** ():
// - consul, nomad, storage, networking
// - System-level configuration and management
// - Hardware abstraction and OS integration
// - Security hardening and compliance
//
// ## Implementation Benefits
//
// **Simplified User Interface:**
// - Single command format for all services
// - Automatic dependency resolution
// - Intelligent defaults and environment detection
// - Consistent error handling and user feedback
//
// **Architectural Flexibility:**
// - Clean separation between application and infrastructure layers
// - Technology-agnostic user interface
// - Easy migration between orchestration technologies
// - Maintainable and testable codebase
//
// **Enhanced Developer Experience:**
// - Reduced cognitive load for users
// - Consistent patterns across all services
// - Clear error messages and troubleshooting guidance
// - Comprehensive logging and audit trails
//
// ## Implementation Status
//
// - ✅ Dual-layer deployment architecture implemented
// - ✅ Automatic service classification operational
// - ✅ Transparent orchestration technology selection active
// - ✅ Consistent user interface across all services implemented
// - ✅ Intelligent defaults and environment detection operational
//
// For detailed CLI implementation, see:
// - cmd/create/ - Service creation commands with abstracted interface
// - pkg/shared/ - Shared CLI utilities and patterns
// - pkg/bootstrap/ - Infrastructure bootstrapping with user abstraction
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// AddStringFlag adds a string flag and optionally marks as required.
// Env/Config are handled by Viper if you call BindFlagsToViper.
func AddStringFlag(cmd *cobra.Command, name, shorthand, def, help string, required bool) {
	cmd.Flags().StringP(name, shorthand, def, help)
	if required {
		if err := cmd.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}
}

// AddBoolFlag adds a boolean flag.
func AddBoolFlag(cmd *cobra.Command, name, shorthand string, def bool, help string) {
	cmd.Flags().BoolP(name, shorthand, def, help)
}

// AddIntFlag adds an int flag.
func AddIntFlag(cmd *cobra.Command, name, shorthand string, def int, help string) {
	cmd.Flags().IntP(name, shorthand, def, help)
}

// AddStringSliceFlag adds a string slice flag.
func AddStringSliceFlag(cmd *cobra.Command, name, shorthand string, def []string, help string, required bool) {
	cmd.Flags().StringSliceP(name, shorthand, def, help)
	if required {
		if err := cmd.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}
}

// BindFlagsToViper binds all flags on a command to a Viper instance.
func BindFlagsToViper(cmd *cobra.Command, v *viper.Viper) error {
	var result error
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if err := v.BindPFlag(f.Name, f); err != nil {
			result = multierror.Append(result, err)
		}
	})
	return result
}

// Optionally, let Viper read env with prefix:
func SetViperEnvPrefix(v *viper.Viper, prefix string) {
	v.SetEnvPrefix(prefix)
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
}

// MustGetString returns the string value, panics if error.
func MustGetString(cmd *cobra.Command, name string) string {
	val, err := cmd.Flags().GetString(name)
	if err != nil {
		panic(fmt.Sprintf("flag error: %v", err))
	}
	if val == "" {
		panic(fmt.Sprintf("required flag --%s is empty", name))
	}
	return val
}

// ShowHelpAndExit prints usage and exits.
func ShowHelpAndExit(cmd *cobra.Command, code int) {
	_ = cmd.Usage()
	os.Exit(code)
}
