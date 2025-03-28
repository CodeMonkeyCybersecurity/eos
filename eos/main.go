/*
main.go

Copyright © 2025 Code Monkey Cybersecurity
Contact: git@cybermonkey.net.au

This file is part of Eos.

This software is dual-licensed under the Do No Harm License
and the GNU Affero General Public License v3 (AGPL-3.0-or-later).
You may use, modify, and distribute it under the terms of either license.

See LICENSE.agpl and LICENSE.dnh for full details.
*/
package main

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/cmd"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
)

func main() {
	logFilePath := logger.ResolveLogPath()
	if err := logger.InitializeWithFallback(logFilePath); err != nil {
		// Fallback failed; explain and exit
		fmt.Fprintf(os.Stderr, "❌ Logging initialization failed: %v\n", err)
		fmt.Fprintln(os.Stderr, "Logging is essential for Eos CLI to run safely. Please provide a writable log file path using --logfile.")
		os.Exit(1)
	}
	defer logger.Sync()
	logger.GetLogger().Info("Eos CLI initialized and ready.")

	cmd.Execute()
}
