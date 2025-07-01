#!/bin/bash
# Emergency zombie service cleanup script
# This script forcefully stops zombie processes that are causing systemd loops

set -euo pipefail

echo "🧹 Emergency Zombie Service Cleanup"
echo "=================================="

# Function to safely kill a process
kill_process_safely() {
    local pid=$1
    local service_name=$2
    
    echo " Attempting to kill PID $pid for service $service_name"
    
    # First try SIGTERM
    if kill -TERM "$pid" 2>/dev/null; then
        echo "   Sent SIGTERM to PID $pid"
        sleep 5
        
        # Check if still running
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "    Process $pid terminated gracefully"
            return 0
        fi
    fi
    
    # If SIGTERM didn't work, use SIGKILL
    echo "   🔨 Process didn't respond to SIGTERM, using SIGKILL"
    if kill -KILL "$pid" 2>/dev/null; then
        echo "   💀 Process $pid forcefully terminated"
        return 0
    else
        echo "    Failed to kill process $pid"
        return 1
    fi
}

# Check for the specific zombie service mentioned in the logs
echo " Checking for delphi-llm-worker zombie process..."

# Find the PID of the zombie process
ZOMBIE_PID=$(pgrep -f "delphi-llm-worker" || echo "")

if [ -n "$ZOMBIE_PID" ]; then
    echo "🧟 Found zombie process: PID $ZOMBIE_PID"
    echo "   Process details:"
    ps -p "$ZOMBIE_PID" -o pid,ppid,cmd || echo "   Could not get process details"
    
    echo "💀 Killing zombie process..."
    if kill_process_safely "$ZOMBIE_PID" "delphi-llm-worker"; then
        echo " Zombie process eliminated"
    else
        echo " Failed to kill zombie process - manual intervention required"
        exit 1
    fi
else
    echo " No delphi-llm-worker zombie process found"
fi

# Check for other potential zombie processes
echo ""
echo " Checking for other potential zombie processes..."

# Common zombie patterns
ZOMBIE_PATTERNS=(
    "llm-worker"
    "delphi-emailer"
    "delphi-worker"
    "python.*delphi"
)

for pattern in "${ZOMBIE_PATTERNS[@]}"; do
    echo "   Checking pattern: $pattern"
    PIDS=$(pgrep -f "$pattern" || echo "")
    
    if [ -n "$PIDS" ]; then
        echo "   Found processes matching $pattern:"
        for pid in $PIDS; do
            # Check if this process has a corresponding systemd unit
            SERVICE_NAME=$(ps -p "$pid" -o cmd --no-headers | grep -o '[a-z-]*worker' | head -1 || echo "unknown")
            
            # Check if systemd unit file exists
            if ! systemctl cat "$SERVICE_NAME" >/dev/null 2>&1; then
                echo "   🧟 Zombie detected: PID $pid (no unit file for $SERVICE_NAME)"
                if kill_process_safely "$pid" "$SERVICE_NAME"; then
                    echo "    Zombie eliminated"
                else
                    echo "    Failed to eliminate zombie"
                fi
            else
                echo "    PID $pid has valid unit file"
            fi
        done
    else
        echo "   No processes found for pattern: $pattern"
    fi
done

# Reload systemd to clear any cached state
echo ""
echo "🔄 Reloading systemd daemon to clear cached state..."
if systemctl daemon-reload; then
    echo " Systemd daemon reloaded"
else
    echo " Failed to reload systemd daemon"
fi

# Check systemd status
echo ""
echo " Checking systemd health..."
if systemctl --failed --quiet; then
    echo "  Some services are in failed state:"
    systemctl --failed --no-pager
else
    echo " No failed services"
fi

echo ""
echo "🎉 Emergency cleanup completed!"
echo ""
echo "💡 To prevent this in the future:"
echo "   1. Always use: eos delphi services cleanup --dry-run"
echo "   2. Then use: eos delphi services cleanup --auto-fix"  
echo "   3. Before running: eos delphi services update --all"
echo ""
echo "📝 Check system logs with: journalctl -u systemd --since '1 hour ago' | grep -i 'looping'"