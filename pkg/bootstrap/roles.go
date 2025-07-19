// pkg/bootstrap/roles.go

package bootstrap

import (
	"fmt"
	"sort"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RoleAssignment contains the result of role calculation
type RoleAssignment struct {
	NodeRoles map[string]environment.Role
	Scale     environment.EnvironmentScale
	Changes   []RoleChange
}

// RoleChange represents a role change for a node
type RoleChange struct {
	Hostname string
	OldRole  environment.Role
	NewRole  environment.Role
}

// RecalculateRoles determines optimal role distribution when adding a new node
func RecalculateRoles(rc *eos_io.RuntimeContext, existingNodes []NodeInfo, newNode NodeInfo) (*RoleAssignment, error) {
	logger := otelzap.Ctx(rc.Ctx)
	totalNodes := len(existingNodes) + 1
	
	logger.Info("Recalculating roles for cluster",
		zap.Int("existing_nodes", len(existingNodes)),
		zap.Int("total_nodes", totalNodes))

	assignment := &RoleAssignment{
		NodeRoles: make(map[string]environment.Role),
		Changes:   []RoleChange{},
	}

	// Determine scale
	switch {
	case totalNodes == 1:
		assignment.Scale = environment.ScaleSingle
	case totalNodes <= 3:
		assignment.Scale = environment.ScaleSmall
	case totalNodes <= 6:
		assignment.Scale = environment.ScaleMedium
	default:
		assignment.Scale = environment.ScaleDistributed
	}

	// Assign roles based on node count
	switch totalNodes {
	case 1:
		assignment.NodeRoles[newNode.Hostname] = environment.RoleMonolith
		
	case 2:
		// First node becomes edge, second becomes core
		if len(existingNodes) == 1 {
			existing := existingNodes[0]
			assignment.NodeRoles[existing.Hostname] = environment.RoleEdge
			assignment.NodeRoles[newNode.Hostname] = environment.RoleCore
			
			// Record change if role changed
			if existing.Role != environment.RoleEdge {
				assignment.Changes = append(assignment.Changes, RoleChange{
					Hostname: existing.Hostname,
					OldRole:  existing.Role,
					NewRole:  environment.RoleEdge,
				})
			}
		}
		
	case 3:
		// Edge, Core, Data pattern
		roles := assignThreeNodeRoles(existingNodes, newNode)
		assignment.NodeRoles = roles
		
		// Check for changes
		for _, node := range existingNodes {
			if newRole, ok := roles[node.Hostname]; ok && newRole != node.Role {
				assignment.Changes = append(assignment.Changes, RoleChange{
					Hostname: node.Hostname,
					OldRole:  node.Role,
					NewRole:  newRole,
				})
			}
		}
		
	default:
		// 4+ nodes - more complex assignment
		roles := assignDistributedRoles(rc, existingNodes, newNode)
		assignment.NodeRoles = roles
		
		// Check for changes
		for _, node := range existingNodes {
			if newRole, ok := roles[node.Hostname]; ok && newRole != node.Role {
				assignment.Changes = append(assignment.Changes, RoleChange{
					Hostname: node.Hostname,
					OldRole:  node.Role,
					NewRole:  newRole,
				})
			}
		}
	}

	logger.Info("Role assignment completed",
		zap.Any("assignments", assignment.NodeRoles),
		zap.Int("changes", len(assignment.Changes)))

	return assignment, nil
}

// assignThreeNodeRoles assigns roles for a 3-node cluster
func assignThreeNodeRoles(existingNodes []NodeInfo, newNode NodeInfo) map[string]environment.Role {
	roles := make(map[string]environment.Role)
	
	// Sort nodes by join time (oldest first)
	allNodes := append(existingNodes, newNode)
	sort.Slice(allNodes, func(i, j int) bool {
		return allNodes[i].JoinedAt.Before(allNodes[j].JoinedAt)
	})
	
	// Assign based on order: Edge, Core, Data
	if len(allNodes) >= 1 {
		roles[allNodes[0].Hostname] = environment.RoleEdge
	}
	if len(allNodes) >= 2 {
		roles[allNodes[1].Hostname] = environment.RoleCore
	}
	if len(allNodes) >= 3 {
		roles[allNodes[2].Hostname] = environment.RoleData
	}
	
	return roles
}

// assignDistributedRoles assigns roles for 4+ node clusters
func assignDistributedRoles(rc *eos_io.RuntimeContext, existingNodes []NodeInfo, newNode NodeInfo) map[string]environment.Role {
	logger := otelzap.Ctx(rc.Ctx)
	roles := make(map[string]environment.Role)
	
	allNodes := append(existingNodes, newNode)
	totalNodes := len(allNodes)
	
	// Count current role distribution
	roleCounts := make(map[environment.Role]int)
	for _, node := range existingNodes {
		roleCounts[node.Role]++
	}
	
	// Determine ideal distribution based on cluster size
	idealDist := calculateIdealDistribution(totalNodes)
	
	logger.Debug("Ideal role distribution",
		zap.Any("ideal", idealDist),
		zap.Any("current", roleCounts))
	
	// Assign roles to minimize changes while approaching ideal distribution
	// Keep existing assignments where possible
	for _, node := range existingNodes {
		roles[node.Hostname] = node.Role
	}
	
	// Determine best role for new node
	// TODO: Add PreferredRole field to NodeInfo when needed
	newNodeRole := determineBestRole(roleCounts, idealDist, "")
	roles[newNode.Hostname] = newNodeRole
	roleCounts[newNodeRole]++
	
	// Rebalance if significantly off ideal
	if shouldRebalance(roleCounts, idealDist) {
		roles = rebalanceRoles(rc, allNodes, idealDist)
	}
	
	return roles
}

// calculateIdealDistribution returns ideal role counts for cluster size
func calculateIdealDistribution(nodeCount int) map[environment.Role]int {
	dist := make(map[environment.Role]int)
	
	switch {
	case nodeCount <= 6:
		// Small-medium cluster
		dist[environment.RoleEdge] = 1
		dist[environment.RoleCore] = 2
		dist[environment.RoleData] = 1
		dist[environment.RoleApp] = nodeCount - 4
		
	case nodeCount <= 10:
		// Medium cluster
		dist[environment.RoleEdge] = 2
		dist[environment.RoleCore] = 2
		dist[environment.RoleData] = 2
		dist[environment.RoleMessage] = 1
		dist[environment.RoleObserve] = 1
		dist[environment.RoleApp] = nodeCount - 8
		
	default:
		// Large cluster
		dist[environment.RoleEdge] = 3
		dist[environment.RoleCore] = 3
		dist[environment.RoleData] = 3
		dist[environment.RoleMessage] = 2
		dist[environment.RoleObserve] = 2
		dist[environment.RoleCompute] = 2
		dist[environment.RoleApp] = nodeCount - 15
	}
	
	// Ensure no negative counts
	for role, count := range dist {
		if count < 0 {
			dist[role] = 0
		}
	}
	
	return dist
}

// determineBestRole selects the best role for a new node
func determineBestRole(current, ideal map[environment.Role]int, preferred string) environment.Role {
	// Check if preferred role is needed
	if preferred != "" {
		prefRole := environment.Role(preferred)
		if idealCount, ok := ideal[prefRole]; ok {
			currentCount := current[prefRole]
			if currentCount < idealCount {
				return prefRole
			}
		}
	}
	
	// Find role that is most under-provisioned
	var bestRole environment.Role
	maxDeficit := -1
	
	// Priority order for role assignment
	roleOrder := []environment.Role{
		environment.RoleEdge,
		environment.RoleCore,
		environment.RoleData,
		environment.RoleMessage,
		environment.RoleObserve,
		environment.RoleCompute,
		environment.RoleApp,
	}
	
	for _, role := range roleOrder {
		idealCount := ideal[role]
		currentCount := current[role]
		deficit := idealCount - currentCount
		
		if deficit > maxDeficit {
			maxDeficit = deficit
			bestRole = role
		}
	}
	
	// Default to app role if no clear choice
	if bestRole == "" {
		bestRole = environment.RoleApp
	}
	
	return bestRole
}

// shouldRebalance determines if roles should be rebalanced
func shouldRebalance(current, ideal map[environment.Role]int) bool {
	// Calculate total deviation from ideal
	totalDeviation := 0
	for role, idealCount := range ideal {
		currentCount := current[role]
		deviation := abs(idealCount - currentCount)
		totalDeviation += deviation
	}
	
	// Rebalance if deviation is significant (> 20% of nodes)
	totalNodes := 0
	for _, count := range current {
		totalNodes += count
	}
	
	return totalDeviation > totalNodes/5
}

// rebalanceRoles performs a complete role rebalancing
func rebalanceRoles(rc *eos_io.RuntimeContext, nodes []NodeInfo, ideal map[environment.Role]int) map[string]environment.Role {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Performing role rebalancing")
	
	roles := make(map[string]environment.Role)
	
	// Sort nodes by join time for now (resource-based sorting can be added later)
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].JoinedAt.Before(nodes[j].JoinedAt)
	})
	
	// Assign roles based on resource requirements
	assignedCounts := make(map[environment.Role]int)
	
	for _, node := range nodes {
		// Find best role for this node based on resources and needs
		role := selectRoleByResources(node, ideal, assignedCounts)
		roles[node.Hostname] = role
		assignedCounts[role]++
	}
	
	return roles
}

// selectRoleByResources chooses role based on node resources
func selectRoleByResources(node NodeInfo, ideal, assigned map[environment.Role]int) environment.Role {
	// For now, use a simplified approach without resource requirements
	// TODO: Add ResourceInfo to NodeInfo struct and use actual resource matching
	// Find roles that need assignment
	var candidates []environment.Role
	
	// Priority order for assignment
	roleOrder := []environment.Role{
		environment.RoleEdge,
		environment.RoleCore,
		environment.RoleData,
		environment.RoleMessage,
		environment.RoleObserve,
		environment.RoleCompute,
		environment.RoleApp,
	}
	
	for _, role := range roleOrder {
		if ideal[role] > assigned[role] {
			candidates = append(candidates, role)
		}
	}
	
	// If no specific match, default to app role
	if len(candidates) == 0 {
		return environment.RoleApp
	}
	
	// Return first suitable candidate
	return candidates[0]
}

// abs returns absolute value
func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// GenerateRoleReport creates a human-readable role assignment report
func GenerateRoleReport(assignment *RoleAssignment) string {
	var report strings.Builder
	
	report.WriteString(fmt.Sprintf("Cluster Scale: %s\n", assignment.Scale))
	report.WriteString(fmt.Sprintf("Total Nodes: %d\n\n", len(assignment.NodeRoles)))
	
	report.WriteString("Role Assignments:\n")
	for hostname, role := range assignment.NodeRoles {
		report.WriteString(fmt.Sprintf("  %s: %s (%s)\n", 
			hostname, role, environment.GetRoleDescription(role)))
	}
	
	if len(assignment.Changes) > 0 {
		report.WriteString("\nRole Changes:\n")
		for _, change := range assignment.Changes {
			report.WriteString(fmt.Sprintf("  %s: %s → %s\n",
				change.Hostname, change.OldRole, change.NewRole))
		}
	}
	
	return report.String()
}