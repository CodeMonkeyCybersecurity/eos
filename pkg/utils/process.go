// pkg/utils/process.go

package utils

import (
	"bytes"
	"os/exec"
)

// GrepProcess returns a list of running processes matching the keyword (case-insensitive).
func grepProcess(keyword string) (string, error) {
	ps := exec.Command("ps", "aux")
	grep := exec.Command("grep", "-i", keyword)

	pipe, err := ps.StdoutPipe()
	if err != nil {
		return "", err
	}
	grep.Stdin = pipe

	var output bytes.Buffer
	grep.Stdout = &output

	if err := ps.Start(); err != nil {
		return "", err
	}
	if err := grep.Start(); err != nil {
		return "", err
	}
	if err := ps.Wait(); err != nil {
		return "", err
	}
	if err := grep.Wait(); err != nil {
		return "", err
	}

	return output.String(), nil
}
