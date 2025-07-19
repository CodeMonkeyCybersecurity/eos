#!/usr/bin/env python3
"""
EOS Role Management Runner
Handles dynamic role calculation and distribution for EOS clusters
"""

import logging
import json
from collections import defaultdict

log = logging.getLogger(__name__)

# Role definitions and requirements
ROLE_REQUIREMENTS = {
    'edge': {'min_cpu': 2, 'min_mem_gb': 4, 'priority': 1},
    'core': {'min_cpu': 4, 'min_mem_gb': 8, 'priority': 2},
    'data': {'min_cpu': 4, 'min_mem_gb': 16, 'priority': 3},
    'message': {'min_cpu': 2, 'min_mem_gb': 8, 'priority': 4},
    'observe': {'min_cpu': 2, 'min_mem_gb': 8, 'priority': 5},
    'compute': {'min_cpu': 8, 'min_mem_gb': 32, 'priority': 6},
    'app': {'min_cpu': 2, 'min_mem_gb': 4, 'priority': 7},
}

# Ideal role distribution by cluster size
IDEAL_DISTRIBUTIONS = {
    1: {'monolith': 1},
    2: {'edge': 1, 'core': 1},
    3: {'edge': 1, 'core': 1, 'data': 1},
    4: {'edge': 1, 'core': 2, 'data': 1},
    5: {'edge': 1, 'core': 2, 'data': 1, 'app': 1},
    6: {'edge': 1, 'core': 2, 'data': 1, 'message': 1, 'app': 1},
    7: {'edge': 2, 'core': 2, 'data': 1, 'message': 1, 'app': 1},
    8: {'edge': 2, 'core': 2, 'data': 2, 'message': 1, 'observe': 1},
    'large': {'edge': 3, 'core': 3, 'data': 3, 'message': 2, 'observe': 2, 'compute': 2}
}


def calculate_distribution(cluster_size, new_node=None, current_roles=None):
    """
    Calculate optimal role distribution for the cluster
    
    Args:
        cluster_size: Total number of nodes in cluster
        new_node: Hostname of new node being added
        current_roles: Dict of current node->role assignments
        
    Returns:
        Dict with role assignments for all nodes
    """
    log.info(f"Calculating role distribution for cluster size {cluster_size}")
    
    # Get all nodes
    all_nodes = __salt__['mine.get']('*', 'grains.items')
    
    if new_node and new_node not in all_nodes:
        # Add placeholder for new node
        all_nodes[new_node] = {
            'id': new_node,
            'cpu_cores': 4,  # Default assumptions
            'mem_gb': 8,
            'role': None
        }
    
    # Get ideal distribution for this cluster size
    if cluster_size <= 8:
        ideal = IDEAL_DISTRIBUTIONS.get(cluster_size, {})
    else:
        ideal = IDEAL_DISTRIBUTIONS['large'].copy()
        # Add extra app nodes for large clusters
        extra_nodes = cluster_size - sum(ideal.values())
        ideal['app'] = ideal.get('app', 0) + extra_nodes
    
    # Sort nodes by resources (highest first)
    nodes_by_resource = sorted(
        all_nodes.items(),
        key=lambda x: (
            x[1].get('cpu_cores', 0),
            x[1].get('mem_gb', 0)
        ),
        reverse=True
    )
    
    # Assign roles
    assignments = {}
    role_counts = defaultdict(int)
    
    # First, preserve existing critical roles if they meet requirements
    if current_roles:
        for node, role in current_roles.items():
            if role in ['edge', 'core', 'data'] and node in all_nodes:
                assignments[node] = role
                role_counts[role] += 1
    
    # Then assign remaining nodes
    for node, grains in nodes_by_resource:
        if node in assignments:
            continue
            
        # Find best role for this node
        assigned = False
        for role in ['edge', 'core', 'data', 'message', 'observe', 'compute', 'app']:
            if ideal.get(role, 0) > role_counts[role]:
                # Check if node meets requirements
                req = ROLE_REQUIREMENTS.get(role, {})
                if (grains.get('cpu_cores', 0) >= req.get('min_cpu', 0) and
                    grains.get('mem_gb', 0) >= req.get('min_mem_gb', 0)):
                    assignments[node] = role
                    role_counts[role] += 1
                    assigned = True
                    break
        
        # Default to app role if nothing else fits
        if not assigned:
            assignments[node] = 'app'
            role_counts['app'] += 1
    
    log.info(f"Role assignments: {assignments}")
    log.info(f"Role counts: {dict(role_counts)}")
    
    return assignments


def apply_role_assignments(assignments):
    """
    Apply role assignments to all nodes
    
    Args:
        assignments: Dict of node->role mappings
        
    Returns:
        Dict with results of applying roles
    """
    results = {}
    
    for node, role in assignments.items():
        log.info(f"Applying role {role} to node {node}")
        
        # Set role grain
        grain_result = __salt__['salt.cmd'](
            node,
            'grains.set',
            ['role', role]
        )
        
        # Apply role state
        state_result = __salt__['salt.cmd'](
            node,
            'state.apply',
            [f'roles.{role}']
        )
        
        results[node] = {
            'role': role,
            'grain_set': grain_result,
            'state_applied': state_result
        }
    
    return results


def get_node_resources(node):
    """
    Get resource information for a specific node
    
    Args:
        node: Node hostname
        
    Returns:
        Dict with cpu_cores, mem_gb, storage_gb
    """
    grains = __salt__['salt.cmd'](node, 'grains.items')
    
    return {
        'cpu_cores': grains.get('num_cpus', 0),
        'mem_gb': int(grains.get('mem_total', 0) / 1024),
        'storage_gb': _get_storage_size(node),
        'os': grains.get('os', ''),
        'osrelease': grains.get('osrelease', '')
    }


def _get_storage_size(node):
    """Get total storage size for a node"""
    try:
        disk_usage = __salt__['salt.cmd'](node, 'disk.usage')
        total_gb = 0
        for mount, info in disk_usage.items():
            if mount == '/':
                total_gb += int(info.get('total', 0) / 1024 / 1024 / 1024)
        return total_gb
    except:
        return 100  # Default assumption


def rebalance_roles(force=False):
    """
    Rebalance roles across the cluster
    
    Args:
        force: Force rebalancing even if distribution is acceptable
        
    Returns:
        Dict with new role assignments
    """
    # Get current state
    all_nodes = __salt__['mine.get']('*', 'grains.items')
    current_roles = {node: grains.get('role') for node, grains in all_nodes.items()}
    cluster_size = len(all_nodes)
    
    # Calculate ideal distribution
    new_assignments = calculate_distribution(cluster_size, current_roles=current_roles)
    
    # Check if rebalancing is needed
    if not force:
        changes_needed = False
        for node, new_role in new_assignments.items():
            if current_roles.get(node) != new_role:
                changes_needed = True
                break
        
        if not changes_needed:
            log.info("No rebalancing needed - current distribution is optimal")
            return current_roles
    
    # Apply new assignments
    return apply_role_assignments(new_assignments)


def validate_cluster_roles():
    """
    Validate that all critical roles are assigned
    
    Returns:
        Dict with validation results
    """
    all_nodes = __salt__['mine.get']('*', 'grains.items')
    role_counts = defaultdict(int)
    
    for node, grains in all_nodes.items():
        role = grains.get('role', 'unknown')
        role_counts[role] += 1
    
    cluster_size = len(all_nodes)
    issues = []
    
    # Check critical roles
    if cluster_size >= 2 and role_counts.get('edge', 0) == 0:
        issues.append("No edge node assigned")
    if cluster_size >= 2 and role_counts.get('core', 0) == 0:
        issues.append("No core node assigned")
    if cluster_size >= 3 and role_counts.get('data', 0) == 0:
        issues.append("No data node assigned")
    
    return {
        'valid': len(issues) == 0,
        'issues': issues,
        'role_counts': dict(role_counts),
        'cluster_size': cluster_size
    }