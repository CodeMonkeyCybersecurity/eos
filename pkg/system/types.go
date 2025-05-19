// pkg/system/types.go

package system

type CreateUserOptions struct {
	Username   string
	Auto       bool
	LoginShell bool
}
