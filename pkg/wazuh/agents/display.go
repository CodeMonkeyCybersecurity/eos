package agents

import "fmt"

// PrintAgentInfo displays agent information
// Migrated from cmd/create/wazuh.go printAgentInfo
func PrintAgentInfo(agent Agent) {
	fmt.Printf("\n Agent %s:\n", agent.ID)
	fmt.Printf("  OS: %s %s (%s)\n", agent.OS.Name, agent.OS.Version, agent.OS.Architecture)
}
