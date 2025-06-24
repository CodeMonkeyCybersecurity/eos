#!/usr/bin/env python3
# /usr/local/bin/ab-test-analyzer.py
# stanley:stanley 0750

"""
A/B Testing Results Analyzer for Delphi Prompt Testing

This script analyzes the metrics collected by the prompt-ab-tester.py worker
and provides statistical insights into prompt effectiveness.

Features:
- Statistical significance testing
- Performance comparison across variants
- Cost analysis and ROI calculations
- Visual reports and summaries
- Experiment health monitoring
- Recommendation engine for optimization

Usage:
    python ab-test-analyzer.py --report daily
    python ab-test-analyzer.py --export csv
    python ab-test-analyzer.py --compare cybersobar delphi_notify_long
"""

import argparse
import json
import logging
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import psycopg2  # type: ignore
    from psycopg2.extras import DictCursor  # type: ignore
except ImportError:
    psycopg2 = None

try:
    from dotenv import load_dotenv  # type: ignore
except ImportError:
    load_dotenv = None

try:
    import pandas as pd  # type: ignore
    import numpy as np  # type: ignore
    from scipy import stats  # type: ignore
    ANALYTICS_AVAILABLE = True
except ImportError:
    ANALYTICS_AVAILABLE = False

# Configuration
if load_dotenv is not None:
    load_dotenv("/opt/stackstorm/packs/delphi/.env")

PG_DSN = os.getenv("PG_DSN")
METRICS_FILE = os.environ.get("METRICS_FILE", "/var/log/stackstorm/ab-test-metrics.log")
OUTPUT_DIR = os.environ.get("AB_TEST_REPORTS_DIR", "/var/log/stackstorm/ab-test-reports")

class ABTestAnalyzer:
    """Analyzer for A/B testing results and metrics"""
    
    def __init__(self):
        self.metrics_data: List[Dict] = []
        self.db_connection = None
        self.logger = self._setup_logging()
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for the analyzer"""
        logger = logging.getLogger("ab-test-analyzer")
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s [%(name)s] %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def load_metrics_from_file(self, hours_back: int = 24) -> bool:
        """Load metrics from the log file"""
        try:
            if not os.path.exists(METRICS_FILE):
                self.logger.warning(f"Metrics file not found: {METRICS_FILE}")
                return False
            
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)
            metrics_count = 0
            
            with open(METRICS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        metric = json.loads(line)
                        
                        # Filter by time if timestamp available
                        if 'timestamp' in metric:
                            timestamp = datetime.fromisoformat(
                                metric['timestamp'].replace('Z', '+00:00')
                            )
                            if timestamp < cutoff_time:
                                continue
                        
                        self.metrics_data.append(metric)
                        metrics_count += 1
                        
                    except json.JSONDecodeError as e:
                        self.logger.warning(f"Invalid JSON in metrics file: {e}")
                        continue
            
            self.logger.info(f"Loaded {metrics_count} metrics from last {hours_back} hours")
            return metrics_count > 0
            
        except Exception as e:
            self.logger.error(f"Error loading metrics from file: {e}")
            return False
    
    def load_metrics_from_database(self, hours_back: int = 24) -> bool:
        """Load metrics from database (alerts table)"""
        if not psycopg2 or not PG_DSN:
            self.logger.warning("Database connection not available")
            return False
        
        try:
            conn = psycopg2.connect(PG_DSN)
            cur = conn.cursor(cursor_factory=DictCursor)
            
            # Query alerts with A/B testing metadata
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)
            
            query = """
            SELECT 
                id as alert_id,
                prompt_sent_at,
                response_received_at,
                prompt_text,
                response_text,
                prompt_tokens,
                completion_tokens,
                total_tokens,
                state
            FROM alerts 
            WHERE prompt_sent_at >= %s 
            AND prompt_text IS NOT NULL
            AND response_text IS NOT NULL
            ORDER BY prompt_sent_at DESC;
            """
            
            cur.execute(query, (cutoff_time,))
            records = cur.fetchall()
            
            for record in records:
                try:
                    # Parse prompt metadata to extract variant info
                    prompt_metadata = json.loads(record['prompt_text'])
                    
                    if 'variant_name' in prompt_metadata:
                        # Calculate response time
                        sent_at = record['prompt_sent_at']
                        received_at = record['response_received_at']
                        response_time = (received_at - sent_at).total_seconds() if received_at and sent_at else 0
                        
                        metric = {
                            'timestamp': sent_at.isoformat(),
                            'alert_id': record['alert_id'],
                            'variant_name': prompt_metadata['variant_name'],
                            'success': True,
                            'response_time': response_time,
                            'prompt_tokens': record['prompt_tokens'] or 0,
                            'completion_tokens': record['completion_tokens'] or 0,
                            'total_tokens': record['total_tokens'] or 0,
                            'source': 'database'
                        }
                        
                        self.metrics_data.append(metric)
                
                except (json.JSONDecodeError, KeyError) as e:
                    continue
            
            cur.close()
            conn.close()
            
            self.logger.info(f"Loaded {len(records)} records from database")
            return len(records) > 0
            
        except Exception as e:
            self.logger.error(f"Error loading metrics from database: {e}")
            return False
    
    def analyze_variant_performance(self) -> Dict:
        """Analyze performance metrics by variant"""
        if not self.metrics_data:
            return {}
        
        variant_stats = defaultdict(lambda: {
            'count': 0,
            'success_count': 0,
            'total_response_time': 0,
            'total_tokens': 0,
            'response_times': [],
            'token_counts': [],
            'error_count': 0
        })
        
        # Aggregate metrics by variant
        for metric in self.metrics_data:
            variant = metric.get('variant_name', 'unknown')
            stats = variant_stats[variant]
            
            stats['count'] += 1
            
            if metric.get('success', False):
                stats['success_count'] += 1
                stats['total_response_time'] += metric.get('response_time', 0)
                stats['total_tokens'] += metric.get('total_tokens', 0)
                stats['response_times'].append(metric.get('response_time', 0))
                stats['token_counts'].append(metric.get('total_tokens', 0))
            else:
                stats['error_count'] += 1
        
        # Calculate derived metrics
        results = {}
        for variant, stats in variant_stats.items():
            success_rate = stats['success_count'] / stats['count'] if stats['count'] > 0 else 0
            avg_response_time = stats['total_response_time'] / stats['success_count'] if stats['success_count'] > 0 else 0
            avg_tokens = stats['total_tokens'] / stats['success_count'] if stats['success_count'] > 0 else 0
            
            # Calculate percentiles if analytics available
            p95_response_time = 0
            p95_tokens = 0
            
            if ANALYTICS_AVAILABLE and stats['response_times']:
                p95_response_time = np.percentile(stats['response_times'], 95)
                p95_tokens = np.percentile(stats['token_counts'], 95)
            
            results[variant] = {
                'total_requests': stats['count'],
                'successful_requests': stats['success_count'],
                'failed_requests': stats['error_count'],
                'success_rate': success_rate,
                'avg_response_time': avg_response_time,
                'p95_response_time': p95_response_time,
                'avg_tokens_per_request': avg_tokens,
                'p95_tokens_per_request': p95_tokens,
                'total_tokens_used': stats['total_tokens']
            }
        
        return results
    
    def statistical_significance_test(self, variant_a: str, variant_b: str) -> Dict:
        """Perform statistical significance test between two variants"""
        if not ANALYTICS_AVAILABLE:
            return {"error": "scipy not available for statistical testing"}
        
        # Filter metrics for each variant
        variant_a_metrics = [m for m in self.metrics_data if m.get('variant_name') == variant_a and m.get('success')]
        variant_b_metrics = [m for m in self.metrics_data if m.get('variant_name') == variant_b and m.get('success')]
        
        if len(variant_a_metrics) < 10 or len(variant_b_metrics) < 10:
            return {"error": "Insufficient data for statistical testing (need at least 10 samples each)"}
        
        # Extract response times
        times_a = [m.get('response_time', 0) for m in variant_a_metrics]
        times_b = [m.get('response_time', 0) for m in variant_b_metrics]
        
        # Extract token counts
        tokens_a = [m.get('total_tokens', 0) for m in variant_a_metrics]
        tokens_b = [m.get('total_tokens', 0) for m in variant_b_metrics]
        
        # Perform t-tests
        response_time_ttest = stats.ttest_ind(times_a, times_b)
        token_ttest = stats.ttest_ind(tokens_a, tokens_b)
        
        return {
            'variant_a': variant_a,
            'variant_b': variant_b,
            'sample_size_a': len(variant_a_metrics),
            'sample_size_b': len(variant_b_metrics),
            'response_time_test': {
                'statistic': response_time_ttest.statistic,
                'p_value': response_time_ttest.pvalue,
                'significant': response_time_ttest.pvalue < 0.05,
                'mean_a': np.mean(times_a),
                'mean_b': np.mean(times_b),
                'improvement': (np.mean(times_a) - np.mean(times_b)) / np.mean(times_a) * 100
            },
            'token_usage_test': {
                'statistic': token_ttest.statistic,
                'p_value': token_ttest.pvalue,
                'significant': token_ttest.pvalue < 0.05,
                'mean_a': np.mean(tokens_a),
                'mean_b': np.mean(tokens_b),
                'improvement': (np.mean(tokens_a) - np.mean(tokens_b)) / np.mean(tokens_a) * 100
            }
        }
    
    def generate_cost_analysis(self, cost_per_1k_tokens: float = 0.002) -> Dict:
        """Generate cost analysis across variants"""
        performance = self.analyze_variant_performance()
        
        cost_analysis = {}
        total_cost = 0
        
        for variant, stats in performance.items():
            variant_cost = (stats['total_tokens_used'] / 1000) * cost_per_1k_tokens
            cost_per_request = variant_cost / stats['total_requests'] if stats['total_requests'] > 0 else 0
            
            cost_analysis[variant] = {
                'total_tokens': stats['total_tokens_used'],
                'total_cost_usd': variant_cost,
                'cost_per_request_usd': cost_per_request,
                'requests_processed': stats['total_requests'],
                'cost_efficiency_ratio': stats['success_rate'] / cost_per_request if cost_per_request > 0 else 0
            }
            
            total_cost += variant_cost
        
        cost_analysis['summary'] = {
            'total_cost_usd': total_cost,
            'total_requests': sum(stats['total_requests'] for stats in performance.values()),
            'avg_cost_per_request': total_cost / sum(stats['total_requests'] for stats in performance.values()) if performance else 0
        }
        
        return cost_analysis
    
    def generate_recommendations(self) -> List[str]:
        """Generate optimization recommendations based on analysis"""
        recommendations = []
        performance = self.analyze_variant_performance()
        
        if not performance:
            return ["No data available for recommendations"]
        
        # Find best performing variant by success rate
        best_success_rate = max(performance.values(), key=lambda x: x['success_rate'])
        best_success_variant = next(k for k, v in performance.items() if v == best_success_rate)
        
        # Find most efficient variant by response time
        successful_variants = {k: v for k, v in performance.items() if v['success_rate'] > 0.8}
        if successful_variants:
            best_time_variant = min(successful_variants.items(), key=lambda x: x[1]['avg_response_time'])
            
            recommendations.append(
                f"Best performing variant: '{best_success_variant}' "
                f"(success rate: {best_success_rate['success_rate']:.1%})"
            )
            
            recommendations.append(
                f"Fastest variant: '{best_time_variant[0]}' "
                f"(avg response time: {best_time_variant[1]['avg_response_time']:.2f}s)"
            )
        
        # Check for poor performers
        for variant, stats in performance.items():
            if stats['success_rate'] < 0.8:
                recommendations.append(
                    f" Variant '{variant}' has low success rate ({stats['success_rate']:.1%}) - consider review"
                )
            
            if stats['avg_response_time'] > 10:
                recommendations.append(
                    f" Variant '{variant}' has slow response time ({stats['avg_response_time']:.2f}s) - consider optimization"
                )
        
        # Sample size recommendations
        total_requests = sum(stats['total_requests'] for stats in performance.values())
        if total_requests < 100:
            recommendations.append(
                " Collect more data before making final decisions (current sample size: {total_requests})"
            )
        
        return recommendations
    
    def export_results(self, format_type: str = "json", output_file: Optional[str] = None) -> str:
        """Export analysis results to file"""
        results = {
            'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
            'data_points': len(self.metrics_data),
            'variant_performance': self.analyze_variant_performance(),
            'cost_analysis': self.generate_cost_analysis(),
            'recommendations': self.generate_recommendations()
        }
        
        # Ensure output directory exists
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"{OUTPUT_DIR}/ab_test_analysis_{timestamp}.{format_type}"
        
        try:
            if format_type.lower() == "json":
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, default=str)
            
            elif format_type.lower() == "csv" and ANALYTICS_AVAILABLE:
                # Convert to DataFrame and export
                df = pd.DataFrame(self.metrics_data)
                df.to_csv(output_file, index=False)
            
            else:
                # Plain text report
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write("DELPHI A/B TESTING ANALYSIS REPORT\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(f"Generated: {results['analysis_timestamp']}\n")
                    f.write(f"Data Points: {results['data_points']}\n\n")
                    
                    f.write("VARIANT PERFORMANCE:\n")
                    f.write("-" * 20 + "\n")
                    for variant, stats in results['variant_performance'].items():
                        f.write(f"\n{variant}:\n")
                        for key, value in stats.items():
                            f.write(f"  {key}: {value}\n")
                    
                    f.write("\nRECOMMENDATIONS:\n")
                    f.write("-" * 15 + "\n")
                    for rec in results['recommendations']:
                        f.write(f"• {rec}\n")
            
            self.logger.info(f"Results exported to: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"Error exporting results: {e}")
            return ""
    
    def print_summary_report(self):
        """Print a summary report to console"""
        performance = self.analyze_variant_performance()
        cost_analysis = self.generate_cost_analysis()
        recommendations = self.generate_recommendations()
        
        print("\n" + "=" * 60)
        print("DELPHI A/B TESTING SUMMARY REPORT")
        print("=" * 60)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Data Points Analyzed: {len(self.metrics_data)}")
        print()
        
        print("VARIANT PERFORMANCE:")
        print("-" * 30)
        for variant, stats in performance.items():
            print(f"\n {variant.upper()}:")
            print(f"   Requests: {stats['total_requests']}")
            print(f"   Success Rate: {stats['success_rate']:.1%}")
            print(f"   Avg Response Time: {stats['avg_response_time']:.2f}s")
            print(f"   Avg Tokens/Request: {stats['avg_tokens_per_request']:.1f}")
        
        print(f"\n💰 COST ANALYSIS:")
        print("-" * 15)
        print(f"Total Cost: ${cost_analysis['summary']['total_cost_usd']:.4f}")
        print(f"Avg Cost per Request: ${cost_analysis['summary']['avg_cost_per_request']:.4f}")
        
        print(f"\n🎯 RECOMMENDATIONS:")
        print("-" * 18)
        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. {rec}")
        
        print("\n" + "=" * 60)

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description="Delphi A/B Testing Analyzer")
    parser.add_argument("--hours", type=int, default=24, help="Hours of data to analyze (default: 24)")
    parser.add_argument("--source", choices=["file", "database", "both"], default="both", 
                       help="Data source for analysis")
    parser.add_argument("--export", choices=["json", "csv", "txt"], help="Export results to file")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--compare", nargs=2, metavar=("VARIANT_A", "VARIANT_B"), 
                       help="Compare two specific variants statistically")
    parser.add_argument("--cost-per-1k-tokens", type=float, default=0.002, 
                       help="Cost per 1000 tokens for cost analysis")
    parser.add_argument("--quiet", action="store_true", help="Suppress console output")
    
    args = parser.parse_args()
    
    analyzer = ABTestAnalyzer()
    
    # Load data
    data_loaded = False
    if args.source in ["file", "both"]:
        data_loaded |= analyzer.load_metrics_from_file(args.hours)
    
    if args.source in ["database", "both"]:
        data_loaded |= analyzer.load_metrics_from_database(args.hours)
    
    if not data_loaded:
        print("No data available for analysis")
        sys.exit(1)
    
    # Specific variant comparison
    if args.compare:
        if not ANALYTICS_AVAILABLE:
            print("Statistical comparison requires scipy and numpy packages")
            sys.exit(1)
        
        result = analyzer.statistical_significance_test(args.compare[0], args.compare[1])
        print(json.dumps(result, indent=2))
        return
    
    # Export results
    if args.export:
        output_file = analyzer.export_results(args.export, args.output)
        if not args.quiet:
            print(f"Results exported to: {output_file}")
    
    # Display summary
    if not args.quiet:
        analyzer.print_summary_report()

if __name__ == "__main__":
    main()