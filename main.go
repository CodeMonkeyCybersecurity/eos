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
	"context"

	"github.com/CodeMonkeyCybersecurity/eos/cmd"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func main() {
	rc := eos_io.NewContext(context.Background(), "eos")
	cmd.Execute(rc)
}
