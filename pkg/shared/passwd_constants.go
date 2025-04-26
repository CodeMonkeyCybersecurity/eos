// pkg/shared/vault_consts.go

package shared

const (
	LowerChars  = "abcdefghijklmnopqrstuvwxyz"
	UpperChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	DigitChars  = "0123456789"
	SymbolChars = "!@#$%&*?" // bash-safe

	AllChars = LowerChars + UpperChars + DigitChars + SymbolChars

	ErrPasswordTooShort       = "password must be at least 12 characters long"
	ErrPasswordMissingClasses = "password must include upper/lower case letters, numbers, and symbols"
)

// Constants for user prompts
const (
	PromptEnterPassword   = "Enter password: "
	PromptConfirmPassword = "Confirm password: "
	PromptUsernameInput   = "Enter username (default: eos): "
	SecretsFilename       = "eos-passwd.json"
)

type UserpassCreds struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// UserSecret holds login and SSH key material for a system user.
type UserSecret struct {
	Username string `json:"username"`
	Password string `json:"password"`
	SSHKey   string `json:"ssh_private_key,omitempty"`
}
