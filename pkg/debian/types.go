// pkg/system/types.go

package debian

type CreateUserOptions struct {
	Username   string
	Auto       bool
	LoginShell bool
}
