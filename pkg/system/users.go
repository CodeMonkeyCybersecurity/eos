// pkg/system/users.go

package system

import (
	"fmt"
	"os/exec"
	"strings"
)

// SetPassword sets the Linux user's password using chpasswd.
func SetPassword(username, password string) error {
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s", username, password))
	return cmd.Run()
}

func UserExists(name string) bool {
	return exec.Command("id", name).Run() == nil
}
