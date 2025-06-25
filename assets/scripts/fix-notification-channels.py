#!/usr/bin/env python3
"""
Notification Channel Standardization Script
Ensures all Delphi workers use consistent PostgreSQL notification channels
"""
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Standard notification channels for the Delphi pipeline
STANDARD_CHANNELS = {
    'new_alert': 'delphi-listener → delphi-agent-enricher',
    'agent_enriched': 'delphi-agent-enricher → llm-worker', 
    'new_response': 'llm-worker → email-structurer',
    'alert_structured': 'email-structurer → email-formatter',
    'alert_formatted': 'email-formatter → email-sender',
    'alert_sent': 'email-sender → final (archive/metrics)'
}

# Worker files and their expected channel configurations
WORKER_CONFIGS = {
    'delphi-listener.py': {
        'notify_channels': ['new_alert'],
        'listen_channels': []
    },
    'delphi-agent-enricher.py': {
        'notify_channels': ['agent_enriched'],
        'listen_channels': ['new_alert']
    },
    'llm-worker.py': {
        'notify_channels': ['new_response'], 
        'listen_channels': ['agent_enriched']
    },
    'email-structurer.py': {
        'notify_channels': ['alert_structured'],
        'listen_channels': ['new_response']
    },
    'email-formatter.py': {
        'notify_channels': ['alert_formatted'],
        'listen_channels': ['alert_structured']
    },
    'email-sender.py': {
        'notify_channels': ['alert_sent'],
        'listen_channels': ['alert_formatted']
    }
}

class ChannelStandardizer:
    """Standardizes notification channels across all workers"""
    
    def __init__(self, workers_dir: str = "/Users/henry/Dev/eos/assets/python_workers"):
        self.workers_dir = Path(workers_dir)
        self.changes_made = []
        self.errors = []
    
    def standardize_all(self):
        """Standardize channels in all worker files"""
        print("🔧 Standardizing Notification Channels")
        print("=" * 50)
        
        for worker_file, config in WORKER_CONFIGS.items():
            worker_path = self.workers_dir / worker_file
            if worker_path.exists():
                print(f"\n📝 Processing {worker_file}")
                self.standardize_worker(worker_path, config)
            else:
                self.errors.append(f"Worker file not found: {worker_file}")
        
        self.print_results()
    
    def standardize_worker(self, worker_path: Path, config: Dict):
        """Standardize channels in a specific worker file"""
        try:
            content = worker_path.read_text()
            original_content = content
            
            # Update LISTEN_CHANNEL definitions
            if config['listen_channels']:
                listen_channel = config['listen_channels'][0]  # Primary listen channel
                content = self.update_listen_channel(content, listen_channel, worker_path.name)
            
            # Update NOTIFY_CHANNEL definitions
            if config['notify_channels']:
                notify_channel = config['notify_channels'][0]  # Primary notify channel
                content = self.update_notify_channel(content, notify_channel, worker_path.name)
            
            # Update pg_notify calls
            for notify_channel in config['notify_channels']:
                content = self.update_pg_notify_calls(content, notify_channel, worker_path.name)
            
            # Update LISTEN statements in code
            for listen_channel in config['listen_channels']:
                content = self.update_listen_statements(content, listen_channel, worker_path.name)
            
            # Write changes if any were made
            if content != original_content:
                # Create backup
                backup_path = worker_path.with_suffix('.py.bak')
                backup_path.write_text(original_content)
                
                # Write updated content
                worker_path.write_text(content)
                self.changes_made.append(f"✅ Updated {worker_path.name} (backup: {backup_path.name})")
            else:
                print(f"   ✅ {worker_path.name} already correct")
                
        except Exception as e:
            self.errors.append(f"Error processing {worker_path.name}: {e}")
    
    def update_listen_channel(self, content: str, channel: str, filename: str) -> str:
        """Update LISTEN_CHANNEL variable definition"""
        patterns = [
            # LISTEN_CHANNEL = "old_channel"
            (r'LISTEN_CHANNEL\s*=\s*["\'][^"\']*["\']', f'LISTEN_CHANNEL = "{channel}"'),
            # LISTEN_CHANNEL="old_channel"
            (r'LISTEN_CHANNEL\s*=\s*["\'][^"\']*["\']', f'LISTEN_CHANNEL = "{channel}"'),
        ]
        
        for pattern, replacement in patterns:
            if re.search(pattern, content):
                new_content = re.sub(pattern, replacement, content)
                if new_content != content:
                    print(f"   📡 Updated LISTEN_CHANNEL to '{channel}'")
                    return new_content
        
        return content
    
    def update_notify_channel(self, content: str, channel: str, filename: str) -> str:
        """Update NOTIFY_CHANNEL variable definition"""
        patterns = [
            # NOTIFY_CHANNEL = "old_channel"
            (r'NOTIFY_CHANNEL\s*=\s*["\'][^"\']*["\']', f'NOTIFY_CHANNEL = "{channel}"'),
        ]
        
        for pattern, replacement in patterns:
            if re.search(pattern, content):
                new_content = re.sub(pattern, replacement, content)
                if new_content != content:
                    print(f"   📢 Updated NOTIFY_CHANNEL to '{channel}'")
                    return new_content
        
        return content
    
    def update_pg_notify_calls(self, content: str, channel: str, filename: str) -> str:
        """Update pg_notify function calls"""
        # Pattern to match pg_notify calls with different channel names
        patterns = [
            # pg_notify('old_channel', payload)
            (r"pg_notify\s*\(\s*['\"](?!{0})[^'\"]*['\"]".format(re.escape(channel)), 
             f"pg_notify('{channel}'"),
            # NOTIFY old_channel, payload  
            (r"NOTIFY\s+(?!{0})\w+".format(re.escape(channel)), 
             f"NOTIFY {channel}"),
        ]
        
        modified = False
        for pattern, replacement in patterns:
            matches = re.findall(pattern, content)
            if matches:
                content = re.sub(pattern, replacement, content)
                modified = True
        
        if modified:
            print(f"   📤 Updated pg_notify calls to use '{channel}'")
        
        return content
    
    def update_listen_statements(self, content: str, channel: str, filename: str) -> str:
        """Update LISTEN statements in SQL code"""
        # Pattern to match LISTEN statements
        patterns = [
            # LISTEN old_channel
            (r"LISTEN\s+(?!{0})\w+".format(re.escape(channel)), f"LISTEN {channel}"),
            # cur.execute("LISTEN old_channel")
            (r'cur\.execute\(["\']LISTEN\s+(?!{0})\w+["\']'.format(re.escape(channel)), 
             f'cur.execute("LISTEN {channel}"'),
        ]
        
        modified = False
        for pattern, replacement in patterns:
            if re.search(pattern, content):
                content = re.sub(pattern, replacement, content)
                modified = True
        
        if modified:
            print(f"   📥 Updated LISTEN statements to use '{channel}'")
        
        return content
    
    def print_results(self):
        """Print standardization results"""
        print("\n" + "=" * 50)
        print("📋 STANDARDIZATION RESULTS")
        print("=" * 50)
        
        if self.changes_made:
            print(f"\n✅ CHANGES MADE ({len(self.changes_made)}):")
            for change in self.changes_made:
                print(f"   {change}")
        
        if self.errors:
            print(f"\n❌ ERRORS ({len(self.errors)}):")
            for error in self.errors:
                print(f"   • {error}")
        
        if not self.changes_made and not self.errors:
            print("\n✅ All workers already use correct notification channels!")
        
        print("\n📡 STANDARD NOTIFICATION FLOW:")
        for channel, description in STANDARD_CHANNELS.items():
            print(f"   {channel:18} → {description}")
        
        print("=" * 50)

def main():
    """Main standardization function"""
    if len(sys.argv) > 1:
        workers_dir = sys.argv[1]
    else:
        workers_dir = "/Users/henry/Dev/eos/assets/python_workers"
    
    standardizer = ChannelStandardizer(workers_dir)
    standardizer.standardize_all()

if __name__ == "__main__":
    main()