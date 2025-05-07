/* pkg/interaction/types.go */

package interaction

type FallbackOption struct {
	Label string // shown to user
	Code  string // passed back to logic
}

type Confirmable interface {
	Summary() string
}

const (
	DefaultYesPrompt  = "Y/n"
	DefaultNoPrompt   = "y/N"
	EnterChoicePrompt = "Enter choice number: "
)

const (
	YesShort = "y"
	YesLong  = "yes"
	NoShort  = "n"
	NoLong   = "no"
)
