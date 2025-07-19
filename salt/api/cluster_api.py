#!/usr/bin/env python3
"""
Salt API endpoints for EOS cluster management and node registration.

This module provides REST API endpoints that allow nodes to register with
the Salt master, request role assignments, and coordinate cluster operations.
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

import salt.client
import salt.config
import salt.runner
from flask import Flask, request, jsonify
from werkzeug.exceptions import BadRequest, Unauthorized, NotFound


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask app
app = Flask(__name__)

# Salt clients
opts = salt.config.master_config('/etc/salt/master')
salt_client = salt.client.LocalClient()
salt_runner = salt.runner.RunnerClient(opts)

# Registration storage (in production, would use database)
REGISTRATION_FILE = '/var/lib/eos/pending_registrations.json'
CLUSTER_CONFIG_FILE = '/etc/eos/cluster.yaml'


def load_pending_registrations() -> Dict[str, Any]:
    """Load pending node registrations from file."""
    if not os.path.exists(REGISTRATION_FILE):
        return {}
    try:
        with open(REGISTRATION_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Failed to load registrations: {e}")
        return {}


def save_pending_registrations(registrations: Dict[str, Any]) -> None:
    """Save pending node registrations to file."""
    os.makedirs(os.path.dirname(REGISTRATION_FILE), exist_ok=True)
    try:
        with open(REGISTRATION_FILE, 'w') as f:
            json.dump(registrations, f, indent=2)
    except IOError as e:
        logger.error(f"Failed to save registrations: {e}")


def get_cluster_info() -> Dict[str, Any]:
    """Get current cluster information."""
    try:
        # Get cluster config
        cluster_config = {}
        if os.path.exists(CLUSTER_CONFIG_FILE):
            import yaml
            with open(CLUSTER_CONFIG_FILE, 'r') as f:
                cluster_config = yaml.safe_load(f) or {}
        
        # Get active minions
        active_minions = salt_client.cmd('*', 'test.ping', timeout=5)
        node_count = len(active_minions) if active_minions else 1
        
        # Calculate cluster scale
        if node_count == 1:
            scale = "single"
        elif node_count <= 3:
            scale = "small"
        elif node_count <= 10:
            scale = "medium"
        else:
            scale = "distributed"
        
        return {
            'cluster_id': cluster_config.get('cluster_id', 'eos-cluster-001'),
            'node_count': node_count,
            'scale': scale,
            'active_minions': list(active_minions.keys()) if active_minions else [],
            'master_addr': cluster_config.get('master_addr', 'localhost'),
            'created_at': cluster_config.get('created_at', datetime.now().isoformat())
        }
    except Exception as e:
        logger.error(f"Failed to get cluster info: {e}")
        return {
            'cluster_id': 'eos-cluster-001',
            'node_count': 1,
            'scale': 'single',
            'active_minions': [],
            'master_addr': 'localhost',
            'created_at': datetime.now().isoformat()
        }


@app.route('/api/v1/cluster/info', methods=['GET'])
def cluster_info():
    """Get cluster information."""
    try:
        info = get_cluster_info()
        return jsonify({
            'status': 'success',
            'data': info
        })
    except Exception as e:
        logger.error(f"Error getting cluster info: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/v1/cluster/register', methods=['POST'])
def register_node():
    """Register a new node with the cluster."""
    try:
        data = request.get_json()
        if not data:
            raise BadRequest("No JSON data provided")
        
        # Validate required fields
        required_fields = ['hostname', 'ip_address']
        for field in required_fields:
            if field not in data:
                raise BadRequest(f"Missing required field: {field}")
        
        hostname = data['hostname']
        ip_address = data['ip_address']
        preferred_role = data.get('preferred_role', '')
        
        # Load existing registrations
        registrations = load_pending_registrations()
        
        # Create registration entry
        registration = {
            'hostname': hostname,
            'ip_address': ip_address,
            'preferred_role': preferred_role,
            'requested_at': datetime.now().isoformat(),
            'status': 'pending',
            'health_checks': data.get('health_checks', {}),
            'capabilities': data.get('capabilities', {}),
            'resources': data.get('resources', {})
        }
        
        # Get cluster info to calculate role
        cluster_info = get_cluster_info()
        
        # Calculate assigned role using Salt runner
        try:
            result = salt_runner.cmd('eos_roles.calculate_distribution', [
                cluster_info['node_count'] + 1,  # Including this new node
                hostname,
                None  # Current roles (will be fetched by runner)
            ])
            
            if result and hostname in result:
                assigned_role = result[hostname]
            else:
                # Fallback role assignment
                if cluster_info['node_count'] == 0:
                    assigned_role = 'monolith'
                elif cluster_info['scale'] == 'small':
                    assigned_role = 'edge'
                else:
                    assigned_role = 'compute'
        except Exception as e:
            logger.warning(f"Role calculation failed, using fallback: {e}")
            assigned_role = 'compute'
        
        registration['assigned_role'] = assigned_role
        
        # Auto-accept if this is the first node or passes basic validation
        auto_accept = (
            cluster_info['node_count'] == 0 or  # First node
            data.get('auto_accept', False)       # Explicitly requested
        )
        
        if auto_accept:
            registration['status'] = 'accepted'
            registration['accepted_at'] = datetime.now().isoformat()
            
            # Accept Salt minion key (if present)
            try:
                # Check if minion key exists
                key_result = salt_runner.cmd('manage.list_keys')
                if hostname in key_result.get('unaccepted', []):
                    # Accept the key
                    accept_result = salt_runner.cmd('manage.accept', [hostname])
                    logger.info(f"Accepted Salt key for {hostname}: {accept_result}")
            except Exception as e:
                logger.warning(f"Failed to accept Salt key for {hostname}: {e}")
        
        # Store registration
        registrations[hostname] = registration
        save_pending_registrations(registrations)
        
        logger.info(f"Node {hostname} registered with role {assigned_role}, status: {registration['status']}")
        
        return jsonify({
            'status': 'success',
            'data': {
                'hostname': hostname,
                'assigned_role': assigned_role,
                'registration_status': registration['status'],
                'cluster_id': cluster_info['cluster_id'],
                'accepted': registration['status'] == 'accepted',
                'cluster_info': cluster_info
            }
        })
        
    except BadRequest as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400
    except Exception as e:
        logger.error(f"Error registering node: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/v1/nodes/<node_id>/accept', methods=['POST'])
def accept_node(node_id: str):
    """Manually accept a pending node registration."""
    try:
        # Load registrations
        registrations = load_pending_registrations()
        
        if node_id not in registrations:
            raise NotFound(f"Node {node_id} not found in pending registrations")
        
        registration = registrations[node_id]
        
        if registration['status'] != 'pending':
            return jsonify({
                'status': 'error',
                'message': f"Node {node_id} is not in pending status"
            }), 400
        
        # Accept the registration
        registration['status'] = 'accepted'
        registration['accepted_at'] = datetime.now().isoformat()
        
        # Accept Salt minion key
        try:
            accept_result = salt_runner.cmd('manage.accept', [node_id])
            logger.info(f"Manually accepted Salt key for {node_id}: {accept_result}")
        except Exception as e:
            logger.warning(f"Failed to accept Salt key for {node_id}: {e}")
        
        # Save updated registration
        registrations[node_id] = registration
        save_pending_registrations(registrations)
        
        # Trigger role orchestration
        try:
            # Run highstate on the new node
            highstate_result = salt_client.cmd(node_id, 'state.highstate', timeout=300)
            logger.info(f"Applied highstate to {node_id}")
        except Exception as e:
            logger.warning(f"Failed to apply highstate to {node_id}: {e}")
        
        return jsonify({
            'status': 'success',
            'data': {
                'hostname': node_id,
                'status': 'accepted',
                'assigned_role': registration['assigned_role']
            }
        })
        
    except NotFound as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 404
    except Exception as e:
        logger.error(f"Error accepting node {node_id}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/v1/nodes', methods=['GET'])
def list_nodes():
    """List all nodes (registered and active)."""
    try:
        # Get active minions
        active_minions = salt_client.cmd('*', 'test.ping', timeout=5)
        
        # Get pending registrations
        registrations = load_pending_registrations()
        
        # Combine information
        nodes = []
        
        # Add active minions
        for minion_id in (active_minions or {}):
            # Get grains
            try:
                grains = salt_client.cmd(minion_id, 'grains.items', timeout=5)
                minion_grains = grains.get(minion_id, {})
                
                nodes.append({
                    'hostname': minion_id,
                    'status': 'active',
                    'role': minion_grains.get('role', 'unknown'),
                    'ip_address': minion_grains.get('ip4_interfaces', {}).get('eth0', ['unknown'])[0],
                    'last_seen': datetime.now().isoformat(),
                    'registration_info': registrations.get(minion_id, {})
                })
            except Exception as e:
                logger.warning(f"Failed to get grains for {minion_id}: {e}")
                nodes.append({
                    'hostname': minion_id,
                    'status': 'active',
                    'role': 'unknown',
                    'ip_address': 'unknown',
                    'last_seen': datetime.now().isoformat(),
                    'registration_info': registrations.get(minion_id, {})
                })
        
        # Add pending registrations not yet active
        for hostname, reg in registrations.items():
            if hostname not in (active_minions or {}):
                nodes.append({
                    'hostname': hostname,
                    'status': reg['status'],
                    'role': reg.get('assigned_role', 'unknown'),
                    'ip_address': reg['ip_address'],
                    'last_seen': reg.get('requested_at', ''),
                    'registration_info': reg
                })
        
        return jsonify({
            'status': 'success',
            'data': {
                'nodes': nodes,
                'total_count': len(nodes),
                'active_count': len(active_minions or {}),
                'pending_count': len([n for n in nodes if n['status'] == 'pending'])
            }
        })
        
    except Exception as e:
        logger.error(f"Error listing nodes: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/v1/roles/calculate', methods=['POST'])
def calculate_roles():
    """Calculate role distribution for cluster."""
    try:
        data = request.get_json() or {}
        cluster_size = data.get('cluster_size')
        new_node = data.get('new_node')
        
        if cluster_size is None:
            # Get current cluster size
            cluster_info = get_cluster_info()
            cluster_size = cluster_info['node_count']
        
        # Use Salt runner to calculate distribution
        result = salt_runner.cmd('eos_roles.calculate_distribution', [
            cluster_size,
            new_node,
            None  # Current roles
        ])
        
        return jsonify({
            'status': 'success',
            'data': {
                'cluster_size': cluster_size,
                'role_distribution': result,
                'new_node': new_node
            }
        })
        
    except Exception as e:
        logger.error(f"Error calculating roles: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """API health check endpoint."""
    try:
        # Test Salt connectivity
        salt_status = 'healthy'
        try:
            salt_client.cmd('*', 'test.ping', timeout=2)
        except Exception:
            salt_status = 'degraded'
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'salt_status': salt_status,
            'api_version': '1.0'
        })
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500


if __name__ == '__main__':
    # Development server
    app.run(host='0.0.0.0', port=5000, debug=False)