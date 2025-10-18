# Wazuh Pipeline Dashboard Architecture

*Last Updated: 2025-01-14*

## Overview

The Wazuh Dashboard is a unified, interactive terminal-based observability platform built with Bubble Tea that provides comprehensive monitoring and management of the Wazuh security alert processing pipeline. It replaces multiple disparate monitoring tools with a single, cohesive interface that offers real-time visibility into all aspects of the system.

## Core Philosophy

**"Single Interface, Complete Visibility"** - The dashboard provides operators with one interface to monitor, troubleshoot, and manage the entire Wazuh pipeline ecosystem, from webhook ingestion to email delivery.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Wazuh Dashboard Hub                         │
├─────────────────────────────────────────────────────────────────┤
│  F1: Pipeline  │  F2: Services  │  F3: Parsers  │  F4: Alerts  │
│     Monitor    │   Management   │  Performance  │   Analysis   │
├─────────────────────────────────────────────────────────────────┤
│                 F5: Performance │ F6: Overview                  │
│                  System Metrics │ Executive Summary              │
└─────────────────────────────────────────────────────────────────┘
```

## Dashboard Modules

### 1. Pipeline Monitor (`eos wazuh dashboard pipeline`)

**Purpose**: Real-time monitoring of alert flow through processing stages

**Features**:
- Visual pipeline flow: `new → enriched → analyzed → structured → formatted → sent`
- Color-coded health indicators (🟢 Healthy, 🟡 Monitor, 🔴 Critical)
- Queue depth monitoring for each stage
- Processing time analytics
- Bottleneck detection with automatic recommendations
- Alert aging analysis

**Views**:
- Pipeline Flow Visualization
- Stage Health Dashboard
- Bottleneck Analysis
- Processing Metrics

### 2. Services Management (`eos wazuh dashboard services`)

**Purpose**: Interactive management of Wazuh pipeline services

**Features**:
- Real-time service status monitoring
- Interactive service control (start/stop/restart/enable/disable)
- Live log streaming with filtering
- Service health metrics (CPU, memory, uptime)
- Dependency checking and validation
- Configuration management
- Deployment operations

**Services Managed**:
- `wazuh-listener` - Webhook receiver
- `wazuh-agent-enricher` - Agent metadata enrichment
- `llm-worker` - LLM processing service
- `email-structurer` - Email structuring with prompt-aware parsing
- `email-formatter` - HTML/text email generation
- `email-sender` - SMTP delivery service
- `parser-monitor` - Parser health monitoring
- `prompt-ab-tester` - A/B testing for prompt optimization

**Interactive Controls**:
- `s` - Start service
- `S` - Stop service
- `r` - Restart service
- `l` - View logs
- `d` - Deploy/update service
- `c` - View configuration
- `h` - Health check

### 3. Parser Performance (`eos wazuh dashboard parsers`)

**Purpose**: Monitoring of prompt-aware parsing system performance

**Features**:
- Parser success rates by type
- Average processing times and throughput
- Circuit breaker status monitoring
- A/B testing results analysis
- Error pattern detection
- Performance optimization recommendations

**Parser Types Monitored**:
- `wazuh_notify_short` - Short notification format
- `security_analysis` - Security incident analysis
- `json_response` - JSON-structured responses
- `conversational` - Natural language responses
- `numbered_list` - Numbered investigation steps
- `hybrid` - Fallback parser

**Circuit Breaker States**:
- 🟢 CLOSED - Normal operation
- 🟡 HALF_OPEN - Testing after failure
- 🔴 OPEN - Protection mode active

### 4. Alert Analysis (`eos wazuh dashboard alerts`)

**Purpose**: Detailed analysis of alert processing and failures

**Features**:
- Recent failure analysis with root cause identification
- Alert correlation and pattern detection
- Processing time distribution analysis
- Success/failure rate trends
- Agent-specific performance metrics
- Rule-level analysis

### 5. Performance Metrics (`eos wazuh dashboard performance`)

**Purpose**: System-level performance monitoring

**Features**:
- CPU and memory usage by service
- Database connection pool metrics
- Network throughput monitoring
- Disk I/O for log files
- PostgreSQL query performance
- Queue depth and processing rates

### 6. Executive Overview (`eos wazuh dashboard overview`)

**Purpose**: High-level operational dashboard for management

**Features**:
- Key performance indicators (KPIs)
- SLA compliance metrics
- Daily/weekly/monthly summaries
- Trend analysis and forecasting
- Alert volume and distribution
- System health score

## Command Interface

### Primary Command
```bash
eos wazuh dashboard [module]
```

### Module Commands
```bash
# Individual module access
eos wazuh dashboard pipeline     # Pipeline monitoring
eos wazuh dashboard services     # Service management  
eos wazuh dashboard parsers      # Parser performance
eos wazuh dashboard alerts       # Alert analysis
eos wazuh dashboard performance  # System metrics
eos wazuh dashboard overview     # Executive summary

# Default: launches overview with navigation
eos wazuh dashboard
```

### Backwards Compatibility
```bash
# Legacy commands remain functional with deprecation warnings
eos wazuh inspect pipeline-functionality  # → dashboard pipeline
eos wazuh services status                 # → dashboard services
eos wazuh parser-health                   # → dashboard parsers
```

## Navigation and Controls

### Universal Navigation
- `F1-F6` - Switch between dashboard modules
- `Tab` - Cycle through UI panels within a module
- `Shift+Tab` - Reverse cycle through panels
- `←/→` or `h/l` - Navigate between views within a module
- `↑/↓` or `k/j` - Navigate within tables and lists
- `?` - Context-sensitive help
- `q` - Quit dashboard
- `r` - Refresh current view
- `Ctrl+R` - Force refresh all data

### Module-Specific Controls
- **Services Module**: `s/S/r/l/d/c/h` for service operations
- **Pipeline Module**: `Space` to pause/resume updates
- **Parsers Module**: `t` to toggle circuit breaker details
- **Alerts Module**: `f` to open failure detail view
- **Performance Module**: `g` to adjust graph time range

## Data Sources and Integration

### PostgreSQL Database
- **Primary Data Source**: Real-time queries against pipeline database
- **Views Used**: `pipeline_health`, `parser_performance`, `recent_failures`
- **Connection Pooling**: Optimized connection management
- **Live Updates**: PostgreSQL LISTEN/NOTIFY for real-time updates

### System Integration
- **Systemd Services**: Direct integration for service management
- **Log Files**: Real-time log streaming via journalctl
- **Process Monitoring**: CPU/memory metrics via procfs
- **Network Monitoring**: Connection status and throughput

### Configuration Sources
- **Environment Variables**: Database connection, API keys
- **Config Files**: Service configurations, A/B testing parameters
- **Vault Integration**: Secure credential retrieval

## Real-time Updates

### Update Mechanisms
- **Database Polling**: Configurable intervals (default: 5 seconds)
- **PostgreSQL Notifications**: Instant updates for state changes
- **Service Status**: Live systemd status monitoring
- **Log Streaming**: Real-time log tail functionality

### Performance Optimization
- **Selective Updates**: Only refresh changed data
- **Background Processing**: Non-blocking data fetching
- **Caching**: Intelligent caching of static data
- **Connection Pooling**: Efficient database connection management

## Visual Design

### Color Scheme
- **Green (#00ff00)**: Healthy, active, successful operations
- **Yellow (#ffaa00)**: Warning, monitoring required, degraded performance
- **Red (#ff0000)**: Critical, failed, requires immediate attention
- **Blue (#00ffff)**: Information, selected items, navigation
- **Gray (#666666)**: Inactive, disabled, or secondary information

### Layout Principles
- **Responsive Design**: Adapts to terminal size changes
- **Information Hierarchy**: Most critical information prominently displayed
- **Consistent Spacing**: Uniform padding and margins across all views
- **Clear Boundaries**: Visual separation between different data sections

### Status Indicators
- **Service Status**: 🟢 Active, 🔴 Inactive,  Failed, ⚫ Not Installed
- **Health Status**: ✓ Healthy, ⚠ Monitor, ✗ Critical
- **Circuit Breakers**: ✓ Closed, ⚠ Half-Open, ✗ Open
- **Processing Flow**: → Active flow, ⊗ Blocked flow

## Error Handling and Resilience

### Connection Failures
- **Database Disconnection**: Automatic reconnection with exponential backoff
- **Service Unavailability**: Graceful degradation with cached data
- **Network Issues**: Timeout handling and retry logic

### Data Validation
- **Input Sanitization**: All user inputs validated before processing
- **Data Integrity**: Verification of database query results
- **Error Recovery**: Automatic recovery from transient failures

### User Experience
- **Error Messages**: Clear, actionable error descriptions
- **Fallback Modes**: Basic functionality when advanced features fail
- **Performance Degradation**: Graceful handling of high load situations

## Security Considerations

### Access Control
- **Environment-based Configuration**: No hardcoded credentials
- **Vault Integration**: Secure credential retrieval
- **Minimal Privileges**: Services run with least required permissions

### Data Protection
- **Sensitive Data Masking**: Automatic masking of credentials in logs
- **Secure Communications**: Encrypted database connections
- **Audit Logging**: Comprehensive logging of all administrative actions

## Monitoring and Observability

### Dashboard Self-Monitoring
- **Performance Metrics**: Dashboard response times and resource usage
- **Error Tracking**: Comprehensive error logging and alerting
- **Usage Analytics**: Tracking of feature usage and user patterns

### Integration with Existing Monitoring
- **OpenTelemetry**: Structured logging and tracing
- **Prometheus Metrics**: Exportable metrics for external monitoring
- **Health Checks**: HTTP endpoints for external health monitoring

## Future Extensibility

### Plugin Architecture
- **Custom Modules**: Framework for adding new dashboard modules
- **External Data Sources**: Integration points for additional data sources
- **Custom Visualizations**: Support for specialized chart types

### API Integration
- **REST API**: Programmatic access to dashboard data
- **WebSocket**: Real-time data streaming for web interfaces
- **GraphQL**: Flexible data querying capabilities

## Migration Strategy

### Phase 1: Foundation (Implemented)
-  Core dashboard framework with module system
-  Pipeline monitoring module (replaces `inspect pipeline-functionality`)
-  Database integration and real-time updates

### Phase 2: Service Integration
-  Services management module (enhances `services` commands)
-  Parser performance module (replaces `parser-health`)
-  Interactive service controls

### Phase 3: Advanced Features
- ⏳ Alert analysis module
- ⏳ Performance metrics module
- ⏳ Executive overview module

### Phase 4: Optimization
- ⏳ Performance optimization and caching
- ⏳ Advanced visualizations
- ⏳ API development

## Success Metrics

### Operational Efficiency
- **Reduced Time to Detection**: Faster identification of pipeline issues
- **Improved Resolution Time**: Quicker problem resolution through integrated tools
- **Decreased Context Switching**: Single interface reduces tool switching overhead

### User Experience
- **User Adoption**: Percentage of operations team using the dashboard
- **Feature Utilization**: Usage statistics for different modules
- **User Satisfaction**: Feedback scores and usability metrics

### System Performance
- **Dashboard Response Time**: Sub-second response for all operations
- **Resource Usage**: Minimal CPU and memory overhead
- **Reliability**: 99.9% uptime and availability

This architecture provides a comprehensive, unified approach to Wazuh pipeline observability while maintaining the flexibility to evolve with changing operational needs.