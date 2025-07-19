#!/usr/bin/env python3
"""
EOS Cluster Management Module
Handles node registration and key acceptance
"""

import json
import logging
import os
import time
from datetime import datetime

log = logging.getLogger(__name__)

# Registration directory
REGISTRATION_DIR = '/var/lib/eos/registrations'


def register_node(node_data):
    """
    Register a new node for cluster joining
    
    Args:
        node_data: Dict containing node registration information
        
    Returns:
        Dict with registration result
    """
    hostname = node_data.get('hostname')
    if not hostname:
        return {'success': False, 'error': 'No hostname provided'}
    
    # Ensure registration directory exists
    if not os.path.exists(REGISTRATION_DIR):
        os.makedirs(REGISTRATION_DIR, mode=0o700)
    
    # Save registration data
    reg_file = os.path.join(REGISTRATION_DIR, f"{hostname}.json")
    node_data['registration_time'] = datetime.utcnow().isoformat()
    node_data['status'] = 'pending'
    
    try:
        with open(reg_file, 'w') as f:
            json.dump(node_data, f, indent=2)
        
        log.info(f"Node registration received for {hostname}")
        
        # Trigger key acceptance if auto-accept is enabled
        if __salt__['config.get']('eos:auto_accept_nodes', False):
            accept_result = auto_accept_node(hostname)
            return {
                'success': True,
                'message': f'Node {hostname} registered',
                'auto_accepted': accept_result.get('success', False)
            }
        
        return {
            'success': True,
            'message': f'Node {hostname} registered, awaiting manual acceptance'
        }
        
    except Exception as e:
        log.error(f"Failed to register node {hostname}: {e}")
        return {'success': False, 'error': str(e)}


def auto_accept_node(hostname):
    """
    Automatically accept a node's key after validation
    
    Args:
        hostname: Node hostname
        
    Returns:
        Dict with acceptance result
    """
    # Check if key is pending
    pending_keys = __salt__['wheel.key.list']().get('minions_pre', [])
    if hostname not in pending_keys:
        return {'success': False, 'error': 'No pending key found'}
    
    # Load registration data
    reg_file = os.path.join(REGISTRATION_DIR, f"{hostname}.json")
    if not os.path.exists(reg_file):
        return {'success': False, 'error': 'No registration data found'}
    
    try:
        with open(reg_file, 'r') as f:
            reg_data = json.load(f)
        
        # Validate registration (basic checks)
        if not validate_registration(reg_data):
            return {'success': False, 'error': 'Registration validation failed'}
        
        # Accept the key
        accept_result = __salt__['wheel.key.accept'](hostname)
        
        if accept_result:
            # Update registration status
            reg_data['status'] = 'accepted'
            reg_data['accepted_time'] = datetime.utcnow().isoformat()
            with open(reg_file, 'w') as f:
                json.dump(reg_data, f, indent=2)
            
            # Trigger role assignment
            __salt__['event.send'](
                'eos/node/accepted',
                {
                    'hostname': hostname,
                    'registration': reg_data
                }
            )
            
            log.info(f"Auto-accepted key for node {hostname}")
            return {'success': True, 'message': f'Key accepted for {hostname}'}
        else:
            return {'success': False, 'error': 'Key acceptance failed'}
            
    except Exception as e:
        log.error(f"Failed to auto-accept node {hostname}: {e}")
        return {'success': False, 'error': str(e)}


def validate_registration(reg_data):
    """
    Validate node registration data
    
    Args:
        reg_data: Registration data dict
        
    Returns:
        Boolean indicating if registration is valid
    """
    # Basic validation
    required_fields = ['hostname', 'ip', 'resources']
    for field in required_fields:
        if field not in reg_data:
            log.warning(f"Registration missing required field: {field}")
            return False
    
    # Validate resources
    resources = reg_data.get('resources', {})
    if resources.get('cpu_cores', 0) < 1:
        log.warning("Invalid CPU cores in registration")
        return False
    if resources.get('memory_gb', 0) < 1:
        log.warning("Invalid memory in registration")
        return False
    
    # Additional validation can be added here
    # - Check IP is reachable
    # - Verify hostname resolves
    # - Check for duplicate registrations
    
    return True


def list_pending_nodes():
    """
    List all pending node registrations
    
    Returns:
        List of pending registrations
    """
    if not os.path.exists(REGISTRATION_DIR):
        return []
    
    pending = []
    for filename in os.listdir(REGISTRATION_DIR):
        if filename.endswith('.json'):
            filepath = os.path.join(REGISTRATION_DIR, filename)
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    if data.get('status') == 'pending':
                        pending.append(data)
            except:
                continue
    
    return pending


def accept_pending_node(hostname):
    """
    Manually accept a pending node
    
    Args:
        hostname: Node hostname to accept
        
    Returns:
        Dict with result
    """
    return auto_accept_node(hostname)


def reject_node(hostname, reason=''):
    """
    Reject a node registration
    
    Args:
        hostname: Node hostname
        reason: Rejection reason
        
    Returns:
        Dict with result
    """
    reg_file = os.path.join(REGISTRATION_DIR, f"{hostname}.json")
    if not os.path.exists(reg_file):
        return {'success': False, 'error': 'No registration found'}
    
    try:
        with open(reg_file, 'r') as f:
            reg_data = json.load(f)
        
        reg_data['status'] = 'rejected'
        reg_data['rejected_time'] = datetime.utcnow().isoformat()
        reg_data['rejection_reason'] = reason
        
        with open(reg_file, 'w') as f:
            json.dump(reg_data, f, indent=2)
        
        # Also reject the key if pending
        __salt__['wheel.key.reject'](hostname)
        
        return {'success': True, 'message': f'Node {hostname} rejected'}
        
    except Exception as e:
        return {'success': False, 'error': str(e)}


def get_cluster_info():
    """
    Get current cluster information
    
    Returns:
        Dict with cluster state
    """
    # Get all accepted minions
    minions = __salt__['minion.list']()
    
    # Get role assignments
    roles = {}
    for minion in minions:
        minion_grains = __salt__['salt.cmd'](minion, 'grains.get', ['role'])
        roles[minion] = minion_grains or 'unknown'
    
    # Count by role
    role_counts = {}
    for role in roles.values():
        role_counts[role] = role_counts.get(role, 0) + 1
    
    return {
        'cluster_id': __salt__['config.get']('eos:cluster_id', 'default'),
        'master': __salt__['config.get']('master', 'localhost'),
        'node_count': len(minions),
        'nodes': minions,
        'roles': roles,
        'role_counts': role_counts,
        'scale': _determine_scale(len(minions))
    }


def _determine_scale(node_count):
    """Determine cluster scale based on node count"""
    if node_count == 1:
        return 'single'
    elif node_count <= 3:
        return 'small'
    elif node_count <= 6:
        return 'medium'
    else:
        return 'distributed'