// pkg/cli/cli.go

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
