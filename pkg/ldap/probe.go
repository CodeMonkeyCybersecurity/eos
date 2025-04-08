// pkg/ldap/probe.go
package ldap

import (
	"os/exec"
)

func runLDAPProbe() error {
	cmd := exec.Command("ldapsearch", "-x", "-H", "ldap://localhost", "-b", "", "-s", "base")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

func runLDAPAuthProbe(bindDN, password string) error {
	cmd := exec.Command("ldapsearch", "-x", "-H", "ldap://localhost", "-D", bindDN, "-w", password, "-b", "", "-s", "base")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}
