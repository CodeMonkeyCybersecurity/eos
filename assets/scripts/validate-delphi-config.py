#!/usr/bin/env python3
"""
Delphi Configuration Validator
Validates environment configuration and database connectivity for the Delphi pipeline
"""
import os
import sys
import psycopg2
import json
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv("/opt/stackstorm/packs/delphi/.env")
except:
    pass

class DelphiConfigValidator:
    """Validates Delphi pipeline configuration"""
    
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.info = []
        
    def validate_all(self) -> bool:
        """Run all validation checks"""
        print(" Delphi Configuration Validator")
        print("=" * 50)
        
        # Critical validations
        self.validate_database()
        self.validate_notification_channels()
        self.validate_required_env_vars()
        
        # Important validations
        self.validate_llm_config()
        self.validate_smtp_config()
        self.validate_file_paths()
        
        # Optional validations
        self.validate_parser_config()
        self.validate_security_config()
        
        # Print results
        self.print_results()
        
        return len(self.errors) == 0
    
    def validate_database(self):
        """Validate database connectivity and schema"""
        print("\n Database Configuration")
        
        pg_dsn = os.getenv("PG_DSN")
        if not pg_dsn:
            self.errors.append("PG_DSN environment variable not set")
            return
        
        try:
            conn = psycopg2.connect(pg_dsn)
            with conn.cursor() as cur:
                # Check if alerts table exists
                cur.execute("""
                    SELECT table_name FROM information_schema.tables 
                    WHERE table_name = 'alerts'
                """)
                if not cur.fetchone():
                    self.errors.append("alerts table does not exist")
                    return
                
                # Check alert_state enum
                cur.execute("""
                    SELECT enumlabel FROM pg_enum 
                    WHERE enumtypid = 'alert_state'::regtype 
                    ORDER BY enumsortorder
                """)
                states = [row[0] for row in cur.fetchall()]
                required_states = ['new', 'agent_enriched', 'summarized', 'structured', 'formatted', 'sent']
                missing_states = [s for s in required_states if s not in states]
                
                if missing_states:
                    self.errors.append(f"Missing alert_state enum values: {missing_states}")
                else:
                    self.info.append(f" Alert states: {states}")
                
                # Check required columns
                cur.execute("""
                    SELECT column_name FROM information_schema.columns 
                    WHERE table_name = 'alerts'
                """)
                columns = [row[0] for row in cur.fetchall()]
                required_columns = [
                    'agent_enriched_at', 'structured_at', 'formatted_at',
                    'prompt_type', 'parser_used', 'parser_success'
                ]
                missing_columns = [c for c in required_columns if c not in columns]
                
                if missing_columns:
                    self.errors.append(f"Missing alerts table columns: {missing_columns}")
                else:
                    self.info.append(" All required columns present")
                
                # Check parser_metrics table
                cur.execute("""
                    SELECT table_name FROM information_schema.tables 
                    WHERE table_name = 'parser_metrics'
                """)
                if not cur.fetchone():
                    self.warnings.append("parser_metrics table does not exist")
                else:
                    self.info.append(" parser_metrics table exists")
                
                # Check triggers
                cur.execute("""
                    SELECT trigger_name FROM information_schema.triggers 
                    WHERE event_object_table = 'alerts'
                """)
                triggers = [row[0] for row in cur.fetchall()]
                if not triggers:
                    self.warnings.append("No triggers found on alerts table")
                else:
                    self.info.append(f" Found {len(triggers)} triggers")
            
            conn.close()
            self.info.append(" Database connectivity successful")
            
        except Exception as e:
            self.errors.append(f"Database connection failed: {e}")
    
    def validate_notification_channels(self):
        """Validate PostgreSQL notification setup"""
        print("\n📡 Notification Channels")
        
        # Check if we can test notifications
        pg_dsn = os.getenv("PG_DSN")
        if not pg_dsn:
            return
        
        try:
            conn = psycopg2.connect(pg_dsn)
            with conn.cursor() as cur:
                # Test notification functions exist
                cur.execute("""
                    SELECT routine_name FROM information_schema.routines 
                    WHERE routine_type = 'FUNCTION' 
                    AND routine_name LIKE '%notify%'
                """)
                functions = [row[0] for row in cur.fetchall()]
                
                required_functions = [
                    'trg_alert_new_notify',
                    'trg_alert_agent_enriched_notify', 
                    'trg_alert_response_notify',
                    'trg_alert_structured_notify',
                    'trg_alert_formatted_notify'
                ]
                
                missing_functions = [f for f in required_functions if f not in functions]
                if missing_functions:
                    self.warnings.append(f"Missing notification functions: {missing_functions}")
                else:
                    self.info.append(" All notification functions present")
            
            conn.close()
            
        except Exception as e:
            self.warnings.append(f"Could not validate notification channels: {e}")
    
    def validate_required_env_vars(self):
        """Validate required environment variables"""
        print("\n🔧 Environment Variables")
        
        # Critical variables
        critical_vars = {
            'PG_DSN': 'Database connection string',
        }
        
        # LLM variables (at least one set required)
        llm_vars_openai = ['OPENAI_API_KEY']
        llm_vars_azure = ['AZURE_OPENAI_API_KEY', 'ENDPOINT_URL', 'DEPLOYMENT_NAME']
        
        # Check critical vars
        for var, desc in critical_vars.items():
            if not os.getenv(var):
                self.errors.append(f"Missing critical variable {var}: {desc}")
            else:
                self.info.append(f" {var} is set")
        
        # Check LLM config
        has_openai = all(os.getenv(var) for var in llm_vars_openai)
        has_azure = all(os.getenv(var) for var in llm_vars_azure)
        
        if not (has_openai or has_azure):
            self.errors.append("Missing LLM configuration: Need either OpenAI or Azure OpenAI credentials")
        elif has_openai:
            self.info.append(" OpenAI configuration detected")
        elif has_azure:
            self.info.append(" Azure OpenAI configuration detected")
    
    def validate_llm_config(self):
        """Validate LLM configuration"""
        print("\n LLM Configuration")
        
        prompt_file = os.getenv("PROMPT_FILE", "/srv/eos/system-prompts/default.txt")
        if not Path(prompt_file).exists():
            self.warnings.append(f"Prompt file not found: {prompt_file}")
        else:
            self.info.append(f" Prompt file exists: {prompt_file}")
        
        # Check prompt directory
        prompt_dir = os.getenv("PROMPT_DIR", "/srv/eos/system-prompts/")
        if not Path(prompt_dir).exists():
            self.warnings.append(f"Prompt directory not found: {prompt_dir}")
        else:
            prompt_files = list(Path(prompt_dir).glob("*.txt"))
            self.info.append(f" Found {len(prompt_files)} prompt files in {prompt_dir}")
    
    def validate_smtp_config(self):
        """Validate SMTP configuration"""
        print("\n📧 SMTP Configuration")
        
        smtp_vars = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_FROM']
        missing_smtp = [var for var in smtp_vars if not os.getenv(var)]
        
        if missing_smtp:
            self.warnings.append(f"Missing SMTP variables: {missing_smtp}")
        else:
            self.info.append(" SMTP configuration complete")
    
    def validate_file_paths(self):
        """Validate file paths and directories"""
        print("\n📁 File Paths")
        
        # Check log directory
        log_dir = "/var/log/stackstorm"
        if not Path(log_dir).exists():
            self.warnings.append(f"Log directory does not exist: {log_dir}")
        else:
            self.info.append(f" Log directory exists: {log_dir}")
        
        # Check template path
        template_path = os.getenv("DELPHI_EMAIL_TEMPLATE_PATH", 
                                  "/opt/stackstorm/packs/delphi/email.html")
        if not Path(template_path).exists():
            self.warnings.append(f"Email template not found: {template_path}")
        else:
            self.info.append(f" Email template exists: {template_path}")
    
    def validate_parser_config(self):
        """Validate parser configuration"""
        print("\n Parser Configuration")
        
        # Check circuit breaker settings
        threshold = os.getenv("PARSER_FAILURE_THRESHOLD", "5")
        timeout = os.getenv("PARSER_FAILURE_TIMEOUT", "300")
        
        try:
            threshold_int = int(threshold)
            timeout_int = int(timeout)
            
            if threshold_int < 1 or threshold_int > 20:
                self.warnings.append(f"PARSER_FAILURE_THRESHOLD should be 1-20, got {threshold_int}")
            
            if timeout_int < 60 or timeout_int > 3600:
                self.warnings.append(f"PARSER_FAILURE_TIMEOUT should be 60-3600 seconds, got {timeout_int}")
                
            self.info.append(f" Circuit breaker: {threshold_int} failures, {timeout_int}s timeout")
            
        except ValueError:
            self.errors.append("Invalid parser configuration: threshold and timeout must be integers")
        
        # Check A/B testing
        ab_test = os.getenv("PARSER_AB_TEST_PERCENTAGE", "0")
        try:
            ab_percentage = int(ab_test)
            if 0 <= ab_percentage <= 100:
                self.info.append(f" A/B testing: {ab_percentage}%")
            else:
                self.warnings.append(f"A/B test percentage should be 0-100, got {ab_percentage}")
        except ValueError:
            self.warnings.append("Invalid A/B test percentage: must be integer")
    
    def validate_security_config(self):
        """Validate security configuration"""
        print("\n Security Configuration")
        
        auth_token = os.getenv("WEBHOOK_AUTH_TOKEN")
        if not auth_token:
            self.warnings.append("WEBHOOK_AUTH_TOKEN not set - webhook will be unprotected")
        elif len(auth_token) < 16:
            self.warnings.append("WEBHOOK_AUTH_TOKEN should be at least 16 characters")
        else:
            self.info.append(" Webhook authentication configured")
        
        # Check Wazuh API config
        wazuh_vars = ['WAZUH_API_URL', 'WAZUH_API_USER', 'WAZUH_API_PASSWD']
        missing_wazuh = [var for var in wazuh_vars if not os.getenv(var)]
        
        if missing_wazuh:
            self.warnings.append(f"Missing Wazuh API variables: {missing_wazuh}")
        else:
            self.info.append(" Wazuh API configuration complete")
    
    def print_results(self):
        """Print validation results"""
        print("\n" + "=" * 50)
        print(" VALIDATION RESULTS")
        print("=" * 50)
        
        if self.errors:
            print(f"\n ERRORS ({len(self.errors)}):")
            for error in self.errors:
                print(f"   • {error}")
        
        if self.warnings:
            print(f"\n  WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"   • {warning}")
        
        if self.info:
            print(f"\n SUCCESS ({len(self.info)}):")
            for info in self.info:
                print(f"   • {info}")
        
        print("\n" + "=" * 50)
        
        if not self.errors and not self.warnings:
            print("🎉 ALL CHECKS PASSED - Delphi is ready for production!")
        elif not self.errors:
            print("  WARNINGS FOUND - Delphi should work but check warnings")
        else:
            print(" CRITICAL ERRORS FOUND - Fix errors before running Delphi")
            
        print("=" * 50)

def main():
    """Main validation function"""
    validator = DelphiConfigValidator()
    success = validator.validate_all()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()