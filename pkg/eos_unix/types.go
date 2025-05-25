// pkg/unix/types.go

package eos_unix

type CreateUserOptions struct {
	Username   string
	Auto       bool
	LoginShell bool
}
