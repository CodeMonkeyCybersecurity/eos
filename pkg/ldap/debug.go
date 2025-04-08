// pkg/ldap/debug.go
package ldap

import (
	"os/exec"
)

func RunLDAPProbe() error {
	cmd := exec.Command("ldapsearch", "-x", "-H", "ldap://localhost", "-b", "", "-s", "base")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

func RunLDAPAuthProbe(bindDN, password string) error {
	cmd := exec.Command("ldapsearch", "-x", "-H", "ldap://localhost", "-D", bindDN, "-w", password, "-b", "", "-s", "base")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

func RunLDAPConfigDump() error {
	cmd := exec.Command("ldapsearch", "-Y", "EXTERNAL", "-H", "ldapi:///", "-b", "cn=config")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}
