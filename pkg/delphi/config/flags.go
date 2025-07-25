package config

// Flags holds global configuration flags for Delphi commands
type Flags struct {
	IgnoreHardwareCheck bool
	OverwriteInstall    bool
}

// DefaultFlags returns the default flag values
func DefaultFlags() *Flags {
	return &Flags{
		IgnoreHardwareCheck: false,
		OverwriteInstall:    false,
	}
}
