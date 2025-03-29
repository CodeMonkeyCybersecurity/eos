// pkg/apt/apt.go

package apt

import "github.com/CodeMonkeyCybersecurity/eos/pkg/execute"

func Update() {
	_ = execute.Execute("apt", "update")
	_ = execute.Execute("apt", "autoremove", "--purge", "-y")
	_ = execute.Execute("apt", "autoclean")
}
