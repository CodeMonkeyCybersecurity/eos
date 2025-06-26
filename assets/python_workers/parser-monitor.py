#!/usr/bin/env python3
# /usr/local/bin/parser-monitor.py
"""
Parser Health Monitoring Dashboard
Provides real-time monitoring of the prompt-aware parser system
"""
import os
import sys
import argparse
import psycopg2
from datetime import datetime, timedelta, timezone # Import timezone for consistency
from tabulate import tabulate
from typing import Dict, List, Any

# --- Import sdnotify for Systemd Watchdog Integration ---
try:
    import sdnotify # ADDED: Import sdnotify
except ImportError:
    # Fallback for systems without sdnotify
    sdnotify = None
    print("WARNING: sdnotify module not found. Systemd watchdog integration will be disabled.", file=sys.stderr)

try:
    from dotenv import load_dotenv
    load_dotenv("/opt/stackstorm/packs/delphi/.env")
except:
    pass

PG_DSN = os.getenv("PG_DSN", "")

# --- Initialize Systemd Notifier ---
if sdnotify:
    notifier = sdnotify.SystemdNotifier() # ADDED: Initialize sdnotify notifier
else:
    class DummyNotifier: # Dummy class if sdnotify isn't available
        def notify(self, message):
            pass
    notifier = DummyNotifier()


class ParserMonitor:
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.logger = self._setup_logging() # Initialize logger here
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for the analyzer"""
        logger = logging.getLogger("parser-monitor") # Use a specific logger name
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s [%(name)s] %(message)s" # Added logger name to format
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger

    def connect(self):
        """Connect to database"""
        try:
            conn = psycopg2.connect(self.dsn)
            return conn
        except Exception as e:
            self.logger.critical(f"Failed to connect to PostgreSQL: {e}") # Log critical error
            notifier.notify(f"STATUS=CRITICAL: Failed to connect to DB. Exiting.") # ADDED: sdnotify on DB connection failure
            notifier.notify("STOPPING=1") # ADDED: sdnotify
            sys.exit(1) # Exit if cannot connect to DB

    def get_parser_performance(self, days: int = 7) -> List[Dict]:
        """Get parser performance metrics"""
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        prompt_type,
                        parser_used,
                        COUNT(*) as total_attempts,
                        COUNT(*) FILTER (WHERE success) as successful,
                        COUNT(*) FILTER (WHERE NOT success) as failed,
                        ROUND(
                            (COUNT(*) FILTER (WHERE success)::decimal / COUNT(*)) * 100, 2
                        ) as success_rate,
                        ROUND(AVG(parse_time_ms) FILTER (WHERE success), 2) as avg_parse_time_ms,
                        MAX(created_at) as last_used
                    FROM parser_metrics
                    WHERE created_at > NOW() - INTERVAL '%s days'
                    GROUP BY prompt_type, parser_used
                    ORDER BY prompt_type, total_attempts DESC
                """, (days,))
                columns = [desc[0] for desc in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
    
    def get_circuit_breaker_status(self) -> List[Dict]:
        """Get circuit breaker status"""
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        prompt_type,
                        COUNT(*) FILTER (WHERE NOT success AND created_at > NOW() - INTERVAL '1 hour') as failure_count,
                        MAX(created_at) FILTER (WHERE NOT success) as last_failure,
                        EXTRACT(EPOCH FROM (NOW() - MAX(created_at) FILTER (WHERE NOT success))) as seconds_since_last_failure,
                        CASE 
                            WHEN COUNT(*) FILTER (WHERE NOT success AND created_at > NOW() - INTERVAL '1 hour') >= 5 
                                 AND MAX(created_at) FILTER (WHERE NOT success) > NOW() - INTERVAL '5 minutes'
                            THEN 'OPEN'
                            WHEN COUNT(*) FILTER (WHERE NOT success AND created_at > NOW() - INTERVAL '1 hour') >= 3
                            THEN 'HALF_OPEN'
                            ELSE 'CLOSED'
                        END as circuit_status
                    FROM parser_metrics
                    WHERE created_at > NOW() - INTERVAL '24 hours'
                    GROUP BY prompt_type
                    HAVING COUNT(*) FILTER (WHERE NOT success) > 0
                    ORDER BY failure_count DESC
                """)
                columns = [desc[0] for desc in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
    
    def get_recent_failures(self, limit: int = 10) -> List[Dict]:
        """Get recent parser failures"""
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        alert_id,
                        prompt_type,
                        parser_used,
                        error,
                        created_at
                    FROM parser_metrics
                    WHERE success = FALSE
                    ORDER BY created_at DESC
                    LIMIT %s
                """, (limit,))
                columns = [desc[0] for desc in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
    
    def get_prompt_distribution(self) -> List[Dict]:
        """Get prompt type distribution"""
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        COALESCE(prompt_type, 'None') as prompt_type,
                        COUNT(*) as alert_count,
                        COUNT(*) FILTER (WHERE state = 'sent') as sent_count,
                        AVG(
                            CASE 
                                WHEN structured_at IS NOT NULL AND response_received_at IS NOT NULL 
                                THEN EXTRACT(EPOCH FROM (COALESCE(structured_at, NOW()) - response_received_at))
                                ELSE NULL 
                            END
                        ) as avg_total_time_sec
                    FROM alerts
                    WHERE created_at > NOW() - INTERVAL '7 days'
                    GROUP BY prompt_type
                    ORDER BY alert_count DESC
                """)
                columns = [desc[0] for desc in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
    
    def get_pipeline_status(self) -> List[Dict]:
        """Get overall pipeline status"""
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        state,
                        COUNT(*) as count,
                        MIN(response_received_at) as oldest,
                        MAX(response_received_at) as newest
                    FROM alerts
                    WHERE response_received_at > NOW() - INTERVAL '24 hours'
                    GROUP BY state
                    ORDER BY 
                        CASE state
                            WHEN 'summarized' THEN 1
                            WHEN 'structured' THEN 2
                            WHEN 'formatted' THEN 3
                            WHEN 'sent' THEN 4
                            WHEN 'send_failed' THEN 5
                            ELSE 6
                        END
                """)
                columns = [desc[0] for desc in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
    
    def get_parser_recommendations(self, limit: int = 20) -> List[Dict]:
        """Get parser recommendation analysis"""
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        pm.prompt_type, # Use alias to avoid ambiguity
                        pm.parser_used as current_parser,
                        CASE 
                            WHEN pm.prompt_type = 'delphi_notify_short' THEN 'DelphiNotifyShortParser'
                            WHEN pm.prompt_type = 'security_analysis' THEN 'SecurityIncidentParser'
                            WHEN pm.prompt_type = 'numbered_investigation' THEN 'NumberedListParser'
                            WHEN pm.prompt_type = 'json_response' THEN 'JSONResponseParser'
                            WHEN pm.prompt_type = 'conversational' THEN 'ConversationalParser'
                            ELSE 'HybridParser'
                        END as recommended_parser,
                        COUNT(*) as mismatch_count
                    FROM parser_metrics pm
                    WHERE pm.success = FALSE # Use alias
                      AND pm.created_at > NOW() - INTERVAL '7 days' # Use alias
                      AND pm.parser_used != CASE 
                            WHEN pm.prompt_type = 'delphi_notify_short' THEN 'DelphiNotifyShortParser'
                            WHEN pm.prompt_type = 'security_analysis' THEN 'SecurityIncidentParser'
                            WHEN pm.prompt_type = 'numbered_investigation' THEN 'NumberedListParser'
                            WHEN pm.prompt_type = 'json_response' THEN 'JSONResponseParser'
                            WHEN pm.prompt_type = 'conversational' THEN 'ConversationalParser'
                            ELSE 'HybridParser'
                        END
                    GROUP BY pm.prompt_type, pm.parser_used
                    ORDER BY mismatch_count DESC
                    LIMIT %s
                """, (limit,))
                columns = [desc[0] for desc in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
    
    def check_missing_prompt_types(self) -> Dict[str, int]:
        """Check for alerts with missing prompt types"""
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        COUNT(*) FILTER (WHERE prompt_type IS NULL) as missing,
                        COUNT(*) FILTER (WHERE prompt_type IS NOT NULL) as has_type,
                        COUNT(*) as total
                    FROM alerts
                    WHERE state IN ('summarized', 'structured', 'formatted')
                      AND response_received_at > NOW() - INTERVAL '24 hours'
                """)
                result = cur.fetchone()
                return {
                    'missing': result[0],
                    'has_type': result[1],
                    'total': result[2]
                }
    
    def get_parser_health_summary(self) -> Dict[str, Any]:
        """Get overall parser health summary"""
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        COUNT(DISTINCT prompt_type) as active_prompt_types,
                        COUNT(*) as total_parses_24h,
                        COUNT(*) FILTER (WHERE success) as successful_parses_24h,
                        AVG(parse_time_ms) FILTER (WHERE success) as avg_parse_time_ms,
                        MAX(created_at) as last_parse
                    FROM parser_metrics
                    WHERE created_at > NOW() - INTERVAL '24 hours'
                """)
                result = cur.fetchone()
                
                # Get stuck alerts
                cur.execute("""
                    SELECT COUNT(*)
                    FROM alerts
                    WHERE state = 'summarized' 
                      AND response_received_at < NOW() - INTERVAL '1 hour'
                """)
                stuck_count = cur.fetchone()[0]
                
                return {
                    'active_prompt_types': result[0] or 0,
                    'total_parses_24h': result[1] or 0,
                    'successful_parses_24h': result[2] or 0,
                    'success_rate_24h': (result[2] / result[1] * 100) if result[1] and result[1] > 0 else 0, # Handle division by zero
                    'avg_parse_time_ms': round(result[3], 2) if result[3] else 0,
                    'last_parse': result[4],
                    'stuck_alerts': stuck_count
                }
    
    def display_dashboard(self):
        """Display complete monitoring dashboard"""
        print("\n" + "="*80)
        print("DELPHI PARSER MONITORING DASHBOARD")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80)
        
        # Health Summary
        print("\n🏥 PARSER HEALTH SUMMARY")
        print("-" * 80)
        health = self.get_parser_health_summary()
        print(f"Active Prompt Types: {health['active_prompt_types']}")
        print(f"24h Parse Success Rate: {health['success_rate_24h']:.1f}% ({health['successful_parses_24h']}/{health['total_parses_24h']})")
        print(f"Average Parse Time: {health['avg_parse_time_ms']}ms")
        print(f"Last Parse: {health['last_parse'].strftime('%H:%M:%S') if health['last_parse'] else 'Never'}")
        if health['stuck_alerts'] > 0:
            print(f"  Stuck Alerts: {health['stuck_alerts']} alerts waiting >1 hour for processing")
        
        # Pipeline Status
        print("\n PIPELINE STATUS (Last 24 hours)")
        print("-" * 80)
        pipeline = self.get_pipeline_status()
        if pipeline:
            table_data = [[
                row['state'],
                row['count'],
                row['oldest'].strftime('%H:%M:%S') if row['oldest'] else 'N/A',
                row['newest'].strftime('%H:%M:%S') if row['newest'] else 'N/A'
            ] for row in pipeline]
            print(tabulate(table_data, 
                          headers=['State', 'Count', 'Oldest', 'Newest'],
                          tablefmt='grid'))
        
        # Circuit Breaker Status
        print("\n CIRCUIT BREAKER STATUS")
        print("-" * 80)
        breakers = self.get_circuit_breaker_status()
        if breakers:
            for breaker in breakers:
                status_emoji = "🔴" if breaker['circuit_status'] == 'OPEN' else "🟡" if breaker['circuit_status'] == 'HALF_OPEN' else "🟢"
                seconds_ago = int(breaker['seconds_since_last_failure']) if breaker['seconds_since_last_failure'] else 0
                print(f"{status_emoji} {breaker['prompt_type']}: {breaker['circuit_status']} "
                      f"({breaker['failure_count']} failures, "
                      f"last: {seconds_ago}s ago)")
        else:
            print(" All circuits operational")
        
        # Parser Performance
        print("\n📈 PARSER PERFORMANCE (Last 7 days)")
        print("-" * 80)
        performance = self.get_parser_performance()
        if performance:
            table_data = [[
                row['prompt_type'],
                row['parser_used'],
                row['total_attempts'],
                f"{row['success_rate']}%",
                f"{row['avg_parse_time_ms']}ms" if row['avg_parse_time_ms'] else 'N/A'
            ] for row in performance[:10]]  # Top 10
            print(tabulate(table_data,
                          headers=['Prompt Type', 'Parser', 'Attempts', 'Success Rate', 'Avg Time'],
                          tablefmt='grid'))
        
        # Prompt Distribution
        print("\n PROMPT TYPE DISTRIBUTION (Last 7 days)")
        print("-" * 80)
        distribution = self.get_prompt_distribution()
        if distribution:
            table_data = [[
                row['prompt_type'] or 'None',
                row['alert_count'],
                row['sent_count'],
                f"{(row['sent_count']/row['alert_count']*100):.1f}%" if row['alert_count'] > 0 else 'N/A',
                f"{row['avg_total_time_sec']:.1f}s" if row['avg_total_time_sec'] else 'N/A'
            ] for row in distribution]
            print(tabulate(table_data,
                          headers=['Prompt Type', 'Total', 'Sent', 'Success %', 'Avg Time'],
                          tablefmt='grid'))
        
        # Missing Prompt Types
        print("\n  MISSING PROMPT TYPES")
        print("-" * 80)
        missing = self.check_missing_prompt_types()
        if missing['missing'] > 0:
            print(f"WARNING: {missing['missing']} alerts have no prompt_type "
                  f"({missing['missing']/missing['total']*100:.1f}% of recent alerts)")
        else:
            print(" All recent alerts have prompt_type assigned")
        
        # Recent Failures
        print("\n RECENT PARSER FAILURES")
        print("-" * 80)
        failures = self.get_recent_failures(5)
        if failures:
            for failure in failures:
                print(f"\n{'='*60}")
                print(f"Alert ID: {failure['alert_id']}")
                print(f"Prompt Type: {failure['prompt_type']}")
                print(f"Parser Used: {failure['parser_used']}")
                print(f"Time: {failure['created_at'].strftime('%Y-%m-%d %H:%M:%S')}") # Ensure datetime format
                print(f"Error: {failure['error'][:100]}...")
        else:
            print(" No recent failures")
        
        # Parser Recommendations
        print("\n💡 PARSER EFFECTIVENESS ANALYSIS")
        print("-" * 80)
        recommendations = self.get_parser_recommendations()
        if recommendations:
            print("Potential parser mismatches detected:")
            table_data = [[
                row['prompt_type'],
                row['current_parser'],
                row['recommended_parser'],
                row['mismatch_count']
            ] for row in recommendations[:5]]
            print(tabulate(table_data,
                          headers=['Prompt Type', 'Current Parser', 'Recommended', 'Count'],
                          tablefmt='grid'))
        else:
            print(" All parsers appear to be correctly matched")
        
        print("\n" + "="*80)
        print("Use 'parser-monitor.py --help' for more options")
        print("="*80 + "\n")

def main():
    parser = argparse.ArgumentParser(description='Monitor Delphi parser health')
    parser.add_argument('--performance', action='store_true', 
                       help='Show detailed parser performance')
    parser.add_argument('--failures', action='store_true',
                       help='Show recent parser failures')
    parser.add_argument('--recommendations', action='store_true',
                       help='Show parser recommendation analysis')
    parser.add_argument('--circuit-breaker', action='store_true',
                       help='Show circuit breaker status')
    parser.add_argument('--health', action='store_true',
                       help='Show health summary only')
    parser.add_argument('--continuous', '-c', action='store_true',
                       help='Run continuously (refresh every 30s)')
    parser.add_argument('--interval', type=int, default=30,
                       help='Refresh interval in seconds (default: 30)')
    
    args = parser.parse_args()
    
    if not PG_DSN:
        print("ERROR: PG_DSN environment variable not set", file=sys.stderr)
        notifier.notify("STATUS=FATAL: PG_DSN environment variable not set. Exiting.") # ADDED: sdnotify
        notifier.notify("STOPPING=1") # ADDED: sdnotify
        sys.exit(1)
    
    monitor = ParserMonitor(PG_DSN)
    
    try:
        if args.continuous:
            import time
            notifier.notify("READY=1") # ADDED: Signal Systemd that the service is ready in continuous mode
            notifier.notify(f"STATUS=Running in continuous mode, refreshing every {args.interval}s...") # ADDED: sdnotify status update
            while True:
                notifier.notify("WATCHDOG=1") # ADDED: Watchdog ping before each refresh cycle
                os.system('clear' if os.name == 'posix' else 'cls')
                monitor.display_dashboard()
                print(f"\nRefreshing in {args.interval} seconds... (Ctrl+C to exit)")
                time.sleep(args.interval)
        elif args.performance:
            performance = monitor.get_parser_performance()
            print(tabulate(performance, headers='keys', tablefmt='grid'))
        elif args.failures:
            failures = monitor.get_recent_failures(20)
            for f in failures:
                print(f"\n{'='*60}")
                print(f"Alert ID: {f['alert_id']}")
                print(f"Prompt Type: {f['prompt_type']}")
                print(f"Parser Used: {f['parser_used']}")
                print(f"Time: {f['created_at']}")
                print(f"Error: {f['error']}")
        elif args.recommendations:
            recs = monitor.get_parser_recommendations()
            print(tabulate(recs, headers='keys', tablefmt='grid'))
        elif args.circuit_breaker:
            breakers = monitor.get_circuit_breaker_status()
            print(tabulate(breakers, headers='keys', tablefmt='grid'))
        elif args.health:
            health = monitor.get_parser_health_summary()
            print(f"Parser Health Summary:")
            print(f"  Success Rate (24h): {health['success_rate_24h']:.1f}%")
            print(f"  Average Parse Time: {health['avg_parse_time_ms']}ms")
            print(f"  Active Prompt Types: {health['active_prompt_types']}")
            print(f"  Stuck Alerts: {health['stuck_alerts']}")
        else:
            monitor.display_dashboard()
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
        notifier.notify("STATUS=Monitoring stopped by user (KeyboardInterrupt).") # ADDED: sdnotify
        notifier.notify("STOPPING=1") # ADDED: sdnotify
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        notifier.notify(f"STATUS=ERROR: An unhandled exception occurred: {e}. See logs.") # ADDED: sdnotify
        notifier.notify("STOPPING=1") # ADDED: sdnotify
        sys.exit(1)

if __name__ == "__main__":
    main()
