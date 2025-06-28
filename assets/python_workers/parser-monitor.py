#!/usr/bin/env python3
# /usr/local/bin/parser-monitor.py
"""
Parser Health Monitoring Dashboard
Provides real-time monitoring of the prompt-aware parser system
Aligned with Delphi pipeline architecture v2
"""
import os
import sys
import argparse
import psycopg2
import logging  # FIXED: Added missing import
from datetime import datetime, timedelta, timezone
from tabulate import tabulate
from typing import Dict, List, Any, Optional

# --- Import sdnotify for Systemd Watchdog Integration ---
try:
    import sdnotify
except ImportError:
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
    notifier = sdnotify.SystemdNotifier()
else:
    class DummyNotifier:
        def notify(self, message):
            pass
    notifier = DummyNotifier()


class ParserMonitor:
    """Monitor for the Delphi alert processing pipeline parser phase"""
    
    # Pipeline states aligned with actual architecture
    PIPELINE_STATES = {
        'enriched': 1,
        'analyzed': 2,
        'structured': 3,
        'formatted': 4,
        'sent': 5,
        'failed': 6,
        'send_failed': 7
    }
    
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.logger = self._setup_logging()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for the monitor"""
        logger = logging.getLogger("parser-monitor")
        logger.setLevel(logging.INFO)
        
        # Prevent duplicate handlers
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                "%(asctime)s %(levelname)s [%(name)s] %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger

    def connect(self):
        """Connect to database with proper error handling"""
        try:
            conn = psycopg2.connect(self.dsn)
            return conn
        except Exception as e:
            self.logger.critical(f"Failed to connect to PostgreSQL: {e}")
            notifier.notify(f"STATUS=CRITICAL: Failed to connect to DB. Exiting.")
            notifier.notify("STOPPING=1")
            sys.exit(1)

    def get_parser_performance(self, days: int = 7) -> List[Dict]:
        """Get parser performance metrics aligned with new schema"""
        with self.connect() as conn:
            with conn.cursor() as cur:
                # FIXED: Removed Python comments from SQL, used proper aliases
                cur.execute("""
                    SELECT 
                        pm.prompt_type,
                        pm.parser_used,
                        COUNT(*) as total_attempts,
                        COUNT(*) FILTER (WHERE pm.success) as successful,
                        COUNT(*) FILTER (WHERE NOT pm.success) as failed,
                        ROUND(
                            (COUNT(*) FILTER (WHERE pm.success)::decimal / 
                             NULLIF(COUNT(*), 0)) * 100, 2
                        ) as success_rate,
                        ROUND(AVG(pm.parse_time_ms) FILTER (WHERE pm.success), 2) as avg_parse_time_ms,
                        MAX(pm.created_at) as last_used
                    FROM parser_metrics pm
                    WHERE pm.created_at > CURRENT_TIMESTAMP - INTERVAL '%s days'
                    GROUP BY pm.prompt_type, pm.parser_used
                    ORDER BY pm.prompt_type, total_attempts DESC
                """, (days,))
                
                columns = [desc[0] for desc in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
    
    def get_circuit_breaker_status(self) -> List[Dict]:
        """Get circuit breaker status with improved time handling"""
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        prompt_type,
                        COUNT(*) FILTER (
                            WHERE NOT success 
                            AND created_at > CURRENT_TIMESTAMP - INTERVAL '1 hour'
                        ) as failure_count,
                        MAX(created_at) FILTER (WHERE NOT success) as last_failure,
                        EXTRACT(EPOCH FROM (
                            CURRENT_TIMESTAMP - MAX(created_at) FILTER (WHERE NOT success)
                        )) as seconds_since_last_failure,
                        CASE 
                            WHEN COUNT(*) FILTER (
                                WHERE NOT success 
                                AND created_at > CURRENT_TIMESTAMP - INTERVAL '1 hour'
                            ) >= 5 
                            AND MAX(created_at) FILTER (WHERE NOT success) > 
                                CURRENT_TIMESTAMP - INTERVAL '5 minutes'
                            THEN 'OPEN'
                            WHEN COUNT(*) FILTER (
                                WHERE NOT success 
                                AND created_at > CURRENT_TIMESTAMP - INTERVAL '1 hour'
                            ) >= 3
                            THEN 'HALF_OPEN'
                            ELSE 'CLOSED'
                        END as circuit_status
                    FROM parser_metrics
                    WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours'
                    GROUP BY prompt_type
                    HAVING COUNT(*) FILTER (WHERE NOT success) > 0
                    ORDER BY failure_count DESC
                """)
                
                columns = [desc[0] for desc in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
    
    def get_recent_failures(self, limit: int = 10) -> List[Dict]:
        """Get recent parser failures with enhanced error details"""
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        pm.alert_id,
                        pm.prompt_type,
                        pm.parser_used,
                        pm.error,
                        pm.created_at,
                        a.rule_description,
                        a.agent_name
                    FROM parser_metrics pm
                    LEFT JOIN alerts a ON pm.alert_id = a.id
                    WHERE pm.success = FALSE
                    ORDER BY pm.created_at DESC
                    LIMIT %s
                """, (limit,))
                
                columns = [desc[0] for desc in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
    
    def get_prompt_distribution(self) -> List[Dict]:
        """Get prompt type distribution with A/B testing awareness"""
        with self.connect() as conn:
            with conn.cursor() as cur:
                # FIXED: Updated to use correct pipeline states
                cur.execute("""
                    SELECT 
                        COALESCE(a.prompt_type, 'None') as prompt_type,
                        COALESCE(a.experiment_id, 'No Experiment') as experiment,
                        COUNT(*) as alert_count,
                        COUNT(*) FILTER (WHERE a.state = 'sent') as sent_count,
                        COUNT(*) FILTER (WHERE a.state IN ('failed', 'send_failed')) as failed_count,
                        AVG(
                            EXTRACT(EPOCH FROM (
                                COALESCE(a.structured_at, CURRENT_TIMESTAMP) - a.analyzed_at
                            ))
                        ) FILTER (WHERE a.structured_at IS NOT NULL) as avg_parse_time_sec
                    FROM alerts a
                    WHERE a.created_at > CURRENT_TIMESTAMP - INTERVAL '7 days'
                      AND a.state IN ('analyzed', 'structured', 'formatted', 'sent', 'failed')
                    GROUP BY a.prompt_type, a.experiment_id
                    ORDER BY alert_count DESC
                """)
                
                columns = [desc[0] for desc in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
    
    def get_pipeline_status(self) -> List[Dict]:
        """Get overall pipeline status with correct state progression"""
        with self.connect() as conn:
            with conn.cursor() as cur:
                # FIXED: Updated to use correct states and timestamp columns
                cur.execute("""
                    SELECT 
                        state,
                        COUNT(*) as count,
                        MIN(created_at) as oldest,
                        MAX(created_at) as newest,
                        AVG(
                            CASE 
                                WHEN state = 'structured' AND analyzed_at IS NOT NULL 
                                THEN EXTRACT(EPOCH FROM (structured_at - analyzed_at))
                                ELSE NULL 
                            END
                        ) as avg_processing_time
                    FROM alerts
                    WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours'
                    GROUP BY state
                    ORDER BY 
                        CASE state
                            WHEN 'enriched' THEN 1
                            WHEN 'analyzed' THEN 2
                            WHEN 'structured' THEN 3
                            WHEN 'formatted' THEN 4
                            WHEN 'sent' THEN 5
                            WHEN 'failed' THEN 6
                            WHEN 'send_failed' THEN 7
                            ELSE 8
                        END
                """)
                
                columns = [desc[0] for desc in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
    
    def get_parser_recommendations(self, limit: int = 20) -> List[Dict]:
        """Get parser recommendation analysis with fixed SQL"""
        with self.connect() as conn:
            with conn.cursor() as cur:
                # Parser mapping aligned with actual implementation
                parser_mapping = {
                    'delphi_notify': 'DelphiNotifyParser',
                    'isobar': 'ISOBARParser',
                    'security_analysis': 'SecurityIncidentParser',
                    'numbered_investigation': 'NumberedListParser',
                    'json_response': 'JSONResponseParser',
                    'conversational': 'ConversationalParser'
                }
                
                # Build CASE statement for SQL
                case_when = '\n'.join([
                    f"WHEN pm.prompt_type = '{k}' THEN '{v}'"
                    for k, v in parser_mapping.items()
                ])
                
                cur.execute(f"""
                    SELECT 
                        pm.prompt_type,
                        pm.parser_used as current_parser,
                        CASE 
                            {case_when}
                            ELSE 'FallbackParser'
                        END as recommended_parser,
                        COUNT(*) as mismatch_count,
                        AVG(pm.parse_time_ms) as avg_parse_time
                    FROM parser_metrics pm
                    WHERE pm.success = FALSE
                      AND pm.created_at > CURRENT_TIMESTAMP - INTERVAL '7 days'
                      AND pm.parser_used != CASE 
                            {case_when}
                            ELSE 'FallbackParser'
                        END
                    GROUP BY pm.prompt_type, pm.parser_used
                    ORDER BY mismatch_count DESC
                    LIMIT %s
                """, (limit,))
                
                columns = [desc[0] for desc in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
    
    def check_stuck_alerts(self) -> Dict[str, Any]:
        """Check for alerts stuck in various pipeline stages"""
        with self.connect() as conn:
            with conn.cursor() as cur:
                stuck_thresholds = {
                    'analyzed': '1 hour',
                    'structured': '30 minutes',
                    'formatted': '15 minutes'
                }
                
                stuck_counts = {}
                for state, threshold in stuck_thresholds.items():
                    cur.execute("""
                        SELECT COUNT(*), MIN(created_at)
                        FROM alerts
                        WHERE state = %s 
                          AND created_at < CURRENT_TIMESTAMP - INTERVAL %s
                    """, (state, threshold))
                    count, oldest = cur.fetchone()
                    stuck_counts[state] = {
                        'count': count or 0,
                        'oldest': oldest,
                        'threshold': threshold
                    }
                
                return stuck_counts
    
    def get_ab_test_metrics(self) -> List[Dict]:
        """Get A/B testing metrics from the new experiment system"""
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        e.experiment_name,
                        e.variant_name,
                        COUNT(DISTINCT a.id) as alert_count,
                        COUNT(DISTINCT a.id) FILTER (WHERE a.state = 'sent') as success_count,
                        AVG(
                            EXTRACT(EPOCH FROM (a.sent_at - a.created_at))
                        ) FILTER (WHERE a.sent_at IS NOT NULL) as avg_total_time,
                        COUNT(DISTINCT pm.alert_id) FILTER (WHERE pm.success) as parse_success_count
                    FROM alerts a
                    LEFT JOIN experiments e ON a.experiment_id = e.experiment_id
                    LEFT JOIN parser_metrics pm ON a.id = pm.alert_id
                    WHERE a.created_at > CURRENT_TIMESTAMP - INTERVAL '7 days'
                      AND e.experiment_name IS NOT NULL
                    GROUP BY e.experiment_name, e.variant_name
                    ORDER BY e.experiment_name, alert_count DESC
                """)
                
                columns = [desc[0] for desc in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
    
    def get_parser_health_summary(self) -> Dict[str, Any]:
        """Get overall parser health summary with pipeline awareness"""
        with self.connect() as conn:
            with conn.cursor() as cur:
                # Basic metrics
                cur.execute("""
                    SELECT 
                        COUNT(DISTINCT prompt_type) as active_prompt_types,
                        COUNT(*) as total_parses_24h,
                        COUNT(*) FILTER (WHERE success) as successful_parses_24h,
                        AVG(parse_time_ms) FILTER (WHERE success) as avg_parse_time_ms,
                        MAX(created_at) as last_parse
                    FROM parser_metrics
                    WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours'
                """)
                result = cur.fetchone()
                
                # Get stuck alerts by state
                stuck_alerts = self.check_stuck_alerts()
                
                # Get A/B test summary
                cur.execute("""
                    SELECT COUNT(DISTINCT experiment_id)
                    FROM alerts
                    WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours'
                      AND experiment_id IS NOT NULL
                """)
                active_experiments = cur.fetchone()[0] or 0
                
                return {
                    'active_prompt_types': result[0] or 0,
                    'total_parses_24h': result[1] or 0,
                    'successful_parses_24h': result[2] or 0,
                    'success_rate_24h': (result[2] / result[1] * 100) if result[1] and result[1] > 0 else 0,
                    'avg_parse_time_ms': round(result[3] or 0, 2),
                    'last_parse': result[4],
                    'stuck_alerts': stuck_alerts,
                    'active_experiments': active_experiments
                }
    
    def display_dashboard(self):
        """Display complete monitoring dashboard with enhanced metrics"""
        print("\n" + "="*80)
        print("DELPHI PARSER MONITORING DASHBOARD v2.0")
        print(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print("="*80)
        
        # Health Summary
        print("\n🏥 PARSER HEALTH SUMMARY")
        print("-" * 80)
        health = self.get_parser_health_summary()
        print(f"Active Prompt Types: {health['active_prompt_types']}")
        print(f"24h Parse Success Rate: {health['success_rate_24h']:.1f}% ({health['successful_parses_24h']}/{health['total_parses_24h']})")
        print(f"Average Parse Time: {health['avg_parse_time_ms']}ms")
        print(f"Last Parse: {health['last_parse'].strftime('%H:%M:%S') if health['last_parse'] else 'Never'}")
        print(f"Active A/B Experiments: {health['active_experiments']}")
        
        # Stuck alerts
        total_stuck = sum(s['count'] for s in health['stuck_alerts'].values())
        if total_stuck > 0:
            print(f"\n⚠️  STUCK ALERTS: {total_stuck} total")
            for state, info in health['stuck_alerts'].items():
                if info['count'] > 0:
                    print(f"  - {state}: {info['count']} alerts (threshold: {info['threshold']})")
        
        # Pipeline Status
        print("\n📊 PIPELINE STATUS (Last 24 hours)")
        print("-" * 80)
        pipeline = self.get_pipeline_status()
        if pipeline:
            table_data = []
            for row in pipeline:
                avg_time = f"{row['avg_processing_time']:.1f}s" if row['avg_processing_time'] else 'N/A'
                table_data.append([
                    row['state'],
                    row['count'],
                    row['oldest'].strftime('%H:%M:%S') if row['oldest'] else 'N/A',
                    row['newest'].strftime('%H:%M:%S') if row['newest'] else 'N/A',
                    avg_time
                ])
            print(tabulate(table_data, 
                          headers=['State', 'Count', 'Oldest', 'Newest', 'Avg Time'],
                          tablefmt='grid'))
        
        # A/B Test Metrics (NEW)
        print("\n🧪 A/B TESTING METRICS")
        print("-" * 80)
        ab_metrics = self.get_ab_test_metrics()
        if ab_metrics:
            table_data = []
            for row in ab_metrics:
                success_rate = (row['success_count'] / row['alert_count'] * 100) if row['alert_count'] > 0 else 0
                avg_time = f"{row['avg_total_time']:.1f}s" if row['avg_total_time'] else 'N/A'
                table_data.append([
                    row['experiment_name'],
                    row['variant_name'],
                    row['alert_count'],
                    f"{success_rate:.1f}%",
                    avg_time
                ])
            print(tabulate(table_data,
                          headers=['Experiment', 'Variant', 'Alerts', 'Success%', 'Avg Time'],
                          tablefmt='grid'))
        else:
            print("✓ No active A/B tests")
        
        # Circuit Breaker Status
        print("\n🔌 CIRCUIT BREAKER STATUS")
        print("-" * 80)
        breakers = self.get_circuit_breaker_status()
        if breakers:
            for breaker in breakers:
                status_emoji = "🔴" if breaker['circuit_status'] == 'OPEN' else "🟡" if breaker['circuit_status'] == 'HALF_OPEN' else "🟢"
                seconds_ago = int(breaker['seconds_since_last_failure']) if breaker['seconds_since_last_failure'] else 0
                time_str = f"{seconds_ago//60}m {seconds_ago%60}s" if seconds_ago >= 60 else f"{seconds_ago}s"
                print(f"{status_emoji} {breaker['prompt_type']}: {breaker['circuit_status']} "
                      f"({breaker['failure_count']} failures, last: {time_str} ago)")
        else:
            print("✓ All circuits operational")
        
        # Parser Performance
        print("\n📈 PARSER PERFORMANCE (Last 7 days)")
        print("-" * 80)
        performance = self.get_parser_performance()
        if performance:
            table_data = [[
                row['prompt_type'],
                row['parser_used'].replace('Parser', ''),  # Shorten names
                row['total_attempts'],
                f"{row['success_rate'] or 0:.1f}%",
                f"{row['avg_parse_time_ms'] or 0:.0f}ms"
            ] for row in performance[:10]]
            print(tabulate(table_data,
                          headers=['Prompt Type', 'Parser', 'Attempts', 'Success', 'Avg Time'],
                          tablefmt='grid'))
        
        # Recent Failures
        print("\n❌ RECENT PARSER FAILURES")
        print("-" * 80)
        failures = self.get_recent_failures(5)
        if failures:
            for failure in failures:
                print(f"\nAlert ID: {failure['alert_id']}")
                print(f"Rule: {failure['rule_description'] or 'Unknown'}")
                print(f"Agent: {failure['agent_name'] or 'Unknown'}")
                print(f"Parser: {failure['parser_used']} (prompt: {failure['prompt_type']})")
                print(f"Time: {failure['created_at'].strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"Error: {failure['error'][:200]}...")
        else:
            print("✓ No recent failures")
        
        print("\n" + "="*80)
        print("Use 'parser-monitor.py --help' for more options")
        print("="*80 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description='Monitor Delphi parser health and A/B testing performance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  parser-monitor.py                    # Show full dashboard
  parser-monitor.py --continuous       # Auto-refresh every 30s
  parser-monitor.py --health          # Quick health check
  parser-monitor.py --ab-tests        # Show A/B test results
        """
    )
    
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
    parser.add_argument('--ab-tests', action='store_true',
                       help='Show A/B testing metrics')
    parser.add_argument('--stuck', action='store_true',
                       help='Show stuck alerts by state')
    parser.add_argument('--continuous', '-c', action='store_true',
                       help='Run continuously (refresh every 30s)')
    parser.add_argument('--interval', type=int, default=30,
                       help='Refresh interval in seconds (default: 30)')
    
    args = parser.parse_args()
    
    if not PG_DSN:
        print("ERROR: PG_DSN environment variable not set", file=sys.stderr)
        notifier.notify("STATUS=FATAL: PG_DSN environment variable not set. Exiting.")
        notifier.notify("STOPPING=1")
        sys.exit(1)
    
    monitor = ParserMonitor(PG_DSN)
    
    try:
        if args.continuous:
            import time
            notifier.notify("READY=1")
            notifier.notify(f"STATUS=Running in continuous mode, refreshing every {args.interval}s...")
            while True:
                notifier.notify("WATCHDOG=1")
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
        elif args.ab_tests:
            ab_metrics = monitor.get_ab_test_metrics()
            print(tabulate(ab_metrics, headers='keys', tablefmt='grid'))
        elif args.stuck:
            stuck = monitor.check_stuck_alerts()
            for state, info in stuck.items():
                if info['count'] > 0:
                    print(f"{state}: {info['count']} alerts stuck > {info['threshold']}")
        elif args.health:
            health = monitor.get_parser_health_summary()
            print(f"Parser Health Summary:")
            print(f"  Success Rate (24h): {health['success_rate_24h']:.1f}%")
            print(f"  Average Parse Time: {health['avg_parse_time_ms']}ms")
            print(f"  Active Prompt Types: {health['active_prompt_types']}")
            print(f"  Active Experiments: {health['active_experiments']}")
            total_stuck = sum(s['count'] for s in health['stuck_alerts'].values())
            print(f"  Stuck Alerts: {total_stuck}")
        else:
            monitor.display_dashboard()
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
        notifier.notify("STATUS=Monitoring stopped by user (KeyboardInterrupt).")
        notifier.notify("STOPPING=1")
    except Exception as e:
        monitor.logger.error(f"Unhandled exception: {e}", exc_info=True)
        notifier.notify(f"STATUS=ERROR: {e}")
        notifier.notify("STOPPING=1")
        sys.exit(1)

if __name__ == "__main__":
    main()