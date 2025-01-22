/*
Copyright © 2024 Code Monkey Cybersecurity mailto:git@cybermonkey.net.au
*/
package main

import (
	"eos/cmd"
	"eos/pkg/logger"
)

func main() {
	logger.Initialize()
	defer logger.Sync()
	logger.GetLogger().Info("Eos CLI initialized and ready.")

	cmd.Execute()
}
