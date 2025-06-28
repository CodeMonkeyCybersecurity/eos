Delphi Alert Processing Pipeline
Overview: Intelligent Security Alert Communication
The Delphi pipeline transforms raw Wazuh security alerts into intelligent, contextually-aware email notifications using Large Language Model (LLM) enrichment. Think of it as a sophisticated translation service that takes technical security alerts and converts them into clear, actionable communications tailored for different audiences.

Core Architecture Philosophy
Rather than sending the same generic alert to everyone, Delphi intelligently selects different communication approaches based on alert characteristics. A critical system breach might warrant a detailed investigation guide, while a routine policy violation could use a concise executive summary. This intelligent routing ensures that each recipient gets the right level of detail in the right format.

Pipeline States and Flow
Your alerts progress through eight distinct states, each representing a completed processing phase:

new → enriched → analyzed → structured → formatted → sent
                                                    ↓
                                                 failed
                                                    ↓
                                               archived
Each state transition is atomic and tracked with precise timestamps, creating a complete audit trail for every alert that enters your system.

State Definitions
new: Alert just received from Wazuh, contains raw security event data enriched: Agent context added (OS, network info, group memberships)
analyzed: LLM has processed the alert and provided intelligent analysis structured: LLM response parsed into actionable sections (summary, details, recommendations) formatted: Email content generated with proper styling and recipients sent: Successfully delivered to intended recipients failed: Processing failed at some point, requires intervention archived: Successfully processed alerts moved to long-term storage

Database Schema Architecture
Core Tables
agents: Comprehensive tracking of your Wazuh endpoints

Stores agent metadata, network information, and current status
Enables intelligent context enrichment for alerts
Tracks API fetch timestamps for efficient caching
alerts: The backbone of your pipeline

Complete audit trail from ingestion to delivery
Stores raw Wazuh data, LLM interactions, parsing results, and email content
Tracks processing times, token usage, and error conditions
Uses JSONB for flexible data structures that can evolve
parser_metrics: Performance tracking for continuous improvement

Records parsing success rates by prompt type
Tracks processing times and error patterns
Enables data-driven optimization of your LLM prompts
Intelligent Processing Features
Parser Type Selection: Your system can choose from six different communication approaches:

security_analysis: Detailed technical breakdown for security teams
executive_summary: Business-focused summaries for leadership
investigation_guide: Step-by-step response procedures
delphi_notify_short: Concise notifications for routine alerts
hybrid: Adaptive format based on alert characteristics
custom: Specialized formatting for unique requirements
Real-time Coordination: PostgreSQL notification channels enable seamless handoffs between workers:

new_alert: Triggers initial processing
alert_enriched: Signals readiness for LLM analysis
alert_analyzed: Initiates parsing phase
alert_structured: Begins email formatting
alert_formatted: Starts delivery process
Worker Components and Responsibilities
Phase 1: Alert Ingestion
custom-delphi-webhook.py

Entry point for Wazuh webhooks
Validates incoming alert data
Forwards to processing pipeline
alert-to-db.py

Creates initial database record with state = 'new'
Generates unique alert_hash for deduplication
Populates core fields: agent_id, rule_id, rule_level, rule_desc
Stores complete raw alert in raw JSONB field
Triggers new_alert notification
Phase 2: Context Enrichment
delphi-agent-enricher.py

Listens for new_alert notifications
Queries agents table for endpoint context
Updates agent_data JSONB field with enriched information
Sets enriched_at timestamp
Transitions state to 'enriched'
Triggers alert_enriched notification
Phase 3: LLM Analysis
llm-worker.py

Listens for alert_enriched notifications
Selects appropriate prompt_type based on alert characteristics
Constructs intelligent prompts combining alert data with agent context
Manages LLM API interactions with comprehensive error handling
Records detailed metrics: prompt_tokens, completion_tokens, total_tokens
Stores full conversation: prompt_text, response_text
Transitions state to 'analyzed'
Triggers alert_analyzed notification
prompt-ab-tester.py

Coordinates with LLM worker for systematic prompt optimization
Implements A/B testing across different prompt approaches
Records experimental data for analysis
Phase 4: Response Structuring
email-structurer.py

Listens for alert_analyzed notifications
Selects parser based on prompt_type field
Applies specialized parsing logic for each communication format
Extracts structured sections (summary, details, recommendations)
Records performance metrics: parser_duration_ms, parser_success
Stores results in structured_data JSONB field
Handles failures gracefully with detailed error logging
Transitions state to 'structured'
Triggers alert_structured notification
parser-monitor.py

Continuously tracks parsing performance
Records detailed metrics in parser_metrics table
Provides operational intelligence for optimization
Phase 5: Email Formatting
email-formatter.py

Listens for alert_structured notifications
Transforms structured data into professional email content
Applies formatting rules for visual appeal and readability
Manages recipient selection and personalization
Stores complete email in formatted_data JSONB field
Sets formatted_at timestamp
Transitions state to 'formatted'
Triggers alert_formatted notification
Phase 6: Email Delivery
email-sender.py

Listens for alert_formatted notifications
Manages email service provider integration
Handles delivery retries with exponential backoff
Tracks delivery attempts in email_retry_count
Records delivery errors in email_error field
Sets alert_sent_at on successful delivery
Transitions state to 'sent' (success) or 'failed' (exhausted retries)
Orchestration and Monitoring
delphi-listener.py

Central coordination service for the entire pipeline
Maintains persistent connections to all notification channels
Ensures proper handoffs between processing phases
Provides centralized logging and error handling
ab-test-analyzer.py

Analyzes A/B test results for continuous improvement
Examines parser effectiveness across different prompt types
Provides insights for optimizing communication strategies
Operational Monitoring
Your schema includes comprehensive monitoring views that provide real-time operational visibility:

pipeline_health
Real-time dashboard showing alert counts by state, processing times, and health indicators. Automatically flags states where alerts are aging beyond acceptable thresholds.

pipeline_bottlenecks
Identifies where alerts are getting stuck by counting how many have been in each state for extended periods (10 minutes, 30 minutes, 1 hour).

parser_performance
Tracks success rates, average processing times, and usage patterns for each prompt type and parser combination. Essential for optimizing your LLM prompts.

parser_error_analysis
Groups recent parsing errors for pattern detection, helping you identify systematic issues that need attention.

recent_failures
Shows recent failures with automatic diagnostic suggestions, accelerating troubleshooting when problems occur.

failure_summary
High-level failure pattern analysis for understanding systemic issues and trends.

Key Design Principles
Reliability Through State Management: Every processing step is tracked with atomic state transitions. If something fails, you know exactly where and can resume processing without losing work.

Comprehensive Audit Trail: Every LLM interaction, parsing attempt, and delivery attempt is recorded with detailed metrics. This enables both troubleshooting and continuous improvement.

Flexible Data Structures: JSONB fields allow your data structures to evolve as your understanding of the problem space deepens, without requiring schema migrations.

Real-time Coordination: PostgreSQL's notification system enables workers to coordinate in real-time without polling, reducing latency and database load.

Intelligent Processing: The prompt_type system allows you to apply different communication strategies based on alert characteristics, ensuring recipients get appropriately formatted information.

Utility Functions
archive_old_alerts(days_to_keep): Automatically archives successfully sent alerts older than the specified number of days, keeping your active dataset manageable.

get_pipeline_stats(): Returns key operational metrics including 24-hour alert volume, successful deliveries, average processing time, and current backlog size.

Configuration and Deployment
The pipeline is designed to run as a collection of independent Python workers that communicate through your PostgreSQL database. Each worker can be deployed, scaled, and monitored independently, providing operational flexibility.

Workers listen to specific database notification channels and process alerts in their designated phase. The notification system ensures that work flows smoothly from one phase to the next without requiring complex orchestration logic.

Success Metrics
Your pipeline is operating optimally when:

95% of alerts complete end-to-end processing within 5 minutes
Parser success rates exceed 90% for each prompt type
No alerts remain stuck in any state for more than 30 minutes
LLM token usage remains within expected cost parameters
Email delivery success rates exceed 98%
Future Evolution
This architecture is designed to support advanced features like:

Machine learning-based prompt type selection
Dynamic parser selection based on LLM response characteristics
Recipient preference learning for communication style optimization
Advanced A/B testing across the entire pipeline
Integration with additional security tools and notification channels
The Delphi pipeline represents a sophisticated approach to security alert communication that goes far beyond simple forwarding, creating intelligent, contextual communications that help recipients understand and respond to security events effectively.

