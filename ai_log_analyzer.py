#!/usr/bin/env python3
"""
AI Log Analyzer - Simple Implementation
Generates synthetic logs and analyzes them using AI with MS Teams notifications
"""

import asyncio
import json
import logging
import random
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import openai
import os
from dotenv import load_dotenv

class AILogAnalyzer:
    """Simple AI-powered log analysis system"""
    
    def __init__(self):
        # Load environment variables from .env file
        load_dotenv()
        
        self.setup_logging()
        self.setup_ai_client()
        
        # MS Teams webhook URL - from .env file
        self.teams_webhook = os.getenv('TEAMS_WEBHOOK_URL', '')
        
        # Log directory for generated files
        self.log_dir = os.getenv('LOG_DIR', './generated_logs')
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Log types available for generation
        self.log_types = {
            'nginx': 'Nginx web server',
            'java': 'Java application',
            'cicd': 'CI/CD pipeline',
            'system': 'System/OS logs', 
            'kubernetes': 'Kubernetes cluster'
        }
        
        # Severity levels
        self.severity_levels = ['CRITICAL', 'HIGH']
        
    def setup_logging(self):
        """Configure logging with debug level support"""
        # Get log level from environment variable, default to INFO
        log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
        
        # Map string level to logging constant
        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        
        level = level_map.get(log_level, logging.INFO)
        
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ai_log_analyzer.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"📝 Logging initialized at {log_level} level")
        
    def setup_ai_client(self):
        """Setup OpenAI client"""
        openai.api_key = os.getenv('OPENAI_API_KEY')
        if not openai.api_key:
            self.logger.error("❌ OpenAI API key not found. Set OPENAI_API_KEY environment variable.")
            raise ValueError("OpenAI API key required")
            
    async def generate_synthetic_logs(self, log_type: str = None, severity: str = None) -> str:
        """
        Generate synthetic logs using OpenAI and write to file
        
        Args:
            log_type: Type of logs (if None, randomly selected)
            severity: Log severity (if None, randomly selected)
            
        Returns:
            Path to the generated log file
        """
        # Randomly select log type and severity if not provided
        if log_type is None:
            log_type = random.choice(list(self.log_types.keys()))
        if severity is None:
            severity = random.choice(self.severity_levels)
            
        self.logger.info(f"🔧 Generating {severity} {log_type} logs...")
        
        if log_type not in self.log_types:
            raise ValueError(f"Invalid log type. Choose from: {list(self.log_types.keys())}")
            
        # Create specific prompts for each log type
        prompts = {
            'nginx': f"""Generate exactly 15 lines of realistic Nginx {severity} error logs.
Include errors like: 502 Bad Gateway, connection timeouts, SSL certificate issues, upstream server failures.
Format: [timestamp] [error] [pid#tid] *connection_id message, client: IP, server: domain, request: "METHOD /path HTTP/1.1", upstream: "server", host: "domain"
Use realistic timestamps from the last hour.""",

            'java': f"""Generate exactly 15 lines of realistic Java application {severity} error logs.
Include errors like: OutOfMemoryError, NullPointerException, database connection failures, timeout exceptions.
Format: YYYY-MM-DD HH:MM:SS.mmm [THREAD] LEVEL LOGGER - message
Include stack traces for some errors.
Use realistic timestamps from the last hour.""",

            'cicd': f"""Generate exactly 15 lines of realistic CI/CD pipeline {severity} error logs.
Include errors like: build failures, test failures, deployment errors, docker build issues, authentication failures.
Format: [YYYY-MM-DD HH:MM:SS] [STAGE] [LEVEL] message
Include stage names like BUILD, TEST, DEPLOY, SECURITY_SCAN.
Use realistic timestamps from the last hour.""",

            'system': f"""Generate exactly 15 lines of realistic Linux system {severity} error logs.
Include errors like: disk space issues, memory problems, service failures, kernel errors, network issues.
Format: Mon DD HH:MM:SS hostname service[pid]: message
Include services like systemd, kernel, sshd, NetworkManager.
Use realistic timestamps from the last hour.""",

            'kubernetes': f"""Generate exactly 15 lines of realistic Kubernetes {severity} error logs.
Include errors like: pod failures, image pull errors, resource limits, scheduling failures, service mesh issues.
Format: YYYY-MM-DDTHH:MM:SS.mmm component/source message
Include components like kubelet, kube-proxy, etcd, coredns.
Use realistic timestamps from the last hour."""
        }
        
        try:
            response = await asyncio.to_thread(
                openai.ChatCompletion.create,
                model="gpt-3.5-turbo",
                messages=[
                    {
                        "role": "system", 
                        "content": "You are a log generation expert. Generate realistic, properly formatted log entries."
                    },
                    {
                        "role": "user",
                        "content": prompts[log_type]
                    }
                ],
                max_tokens=1500,
                temperature=0.8
            )
            
            generated_logs = response.choices[0].message.content.strip()
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{log_type}_{severity}_{timestamp}.log"
            log_file_path = os.path.join(self.log_dir, filename)
            
            # Write logs to file
            with open(log_file_path, 'w', encoding='utf-8') as f:
                f.write(generated_logs)
            
            self.logger.info(f"✅ Generated {len(generated_logs.split(chr(10)))} lines of {log_type} logs")
            self.logger.info(f"📁 Logs saved to: {log_file_path}")
            
            return log_file_path
            
        except Exception as e:
            self.logger.error(f"❌ Failed to generate logs: {e}")
            raise
            
    async def analyze_logs_with_ai(self, log_file_path: str) -> Dict:
        """
        Analyze logs from file using OpenAI
        
        Args:
            log_file_path: Path to the log file to analyze
            
        Returns:
            Analysis results as dictionary
        """
        self.logger.info(f"🤖 Analyzing logs from file: {log_file_path}")
        
        # Extract log type from filename
        filename = os.path.basename(log_file_path)
        log_type = filename.split('_')[0]
        
        # Read log content from file
        try:
            with open(log_file_path, 'r', encoding='utf-8') as f:
                log_content = f.read().strip()
                
            if not log_content:
                return {
                    'status': 'error',
                    'error': 'Log file is empty',
                    'file_path': log_file_path
                }
                
        except FileNotFoundError:
            return {
                'status': 'error',
                'error': f'Log file not found: {log_file_path}',
                'file_path': log_file_path
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': f'Failed to read log file: {e}',
                'file_path': log_file_path
            }
        
        prompt = f"""
Analyze these {log_type} logs and provide structured insights:

LOGS TO ANALYZE:
{log_content}

Return analysis as valid JSON with this exact structure:
{{
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "summary": "One sentence summary of main issues found",
    "error_patterns": [
        {{"type": "error_category", "count": 3, "severity": "HIGH", "sample": "example log line"}}
    ],
    "performance_issues": [
        {{"issue": "description", "impact": "impact_description", "recommendation": "fix_suggestion"}}
    ],
    "immediate_actions": [
        {{"action": "what_to_do", "priority": "HIGH|MEDIUM|LOW", "estimated_time": "time_estimate"}}
    ],
    "root_causes": [
        {{"cause": "likely_root_cause", "confidence": "percentage", "evidence": "supporting_evidence"}}
    ],
    "trends": [
        {{"pattern": "observed_pattern", "frequency": "how_often", "concern_level": "LOW|MEDIUM|HIGH"}}
    ]
}}

Focus on: Error patterns, performance bottlenecks, security issues, resource problems, service dependencies.
"""

        try:
            response = await asyncio.to_thread(
                openai.ChatCompletion.create,
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert log analyst. Analyze logs and provide actionable insights in valid JSON format."
                    },
                    {
                        "role": "user", 
                        "content": prompt
                    }
                ],
                max_tokens=2000,
                temperature=0.1
            )
            
            analysis_text = response.choices[0].message.content.strip()
            
            # Parse JSON response
            try:
                analysis = json.loads(analysis_text)
                self.logger.info(f"✅ AI analysis completed - Severity: {analysis.get('severity', 'UNKNOWN')}")
                return {
                    'status': 'success',
                    'analysis': analysis,
                    'metadata': {
                        'log_type': log_type,
                        'log_file_path': log_file_path,
                        'analysis_time': datetime.utcnow().isoformat(),
                        'log_lines': len(log_content.split('\n')),
                        'tokens_used': response.usage.total_tokens,
                        'file_size_bytes': os.path.getsize(log_file_path)
                    }
                }
            except json.JSONDecodeError as e:
                self.logger.error(f"❌ Failed to parse AI response as JSON: {e}")
                return {
                    'status': 'error',
                    'error': f'Invalid JSON response: {e}',
                    'raw_response': analysis_text[:500],
                    'file_path': log_file_path
                }
                
        except Exception as e:
            self.logger.error(f"❌ AI analysis failed: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'file_path': log_file_path
            }
            
    async def test_teams_webhook(self) -> bool:
        """
        Test Teams webhook with a simple message to validate configuration
        
        Returns:
            Success status
        """
        if not self.teams_webhook:
            self.logger.error("❌ No Teams webhook URL configured")
            return False
            
        self.logger.info("🧪 Testing Teams webhook configuration...")
        
        # Simple test message
        test_message = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": "AI Log Analyzer - Webhook Test",
            "themeColor": "0078D4",
            "sections": [
                {
                    "activityTitle": "🧪 Webhook Configuration Test",
                    "activitySubtitle": "AI Log Analyzer",
                    "facts": [
                        {"name": "Test Time", "value": datetime.utcnow().isoformat()},
                        {"name": "Status", "value": "Testing webhook connectivity"}
                    ],
                    "text": "This is a test message to verify your Teams webhook is working correctly."
                }
            ]
        }
        
        try:
            self.logger.debug(f"🔍 DEBUG: Testing webhook URL: {self.teams_webhook}")
            
            # Validate URL format
            if not self.teams_webhook.startswith('https://'):
                self.logger.error("❌ Webhook URL must start with https://")
                return False
                
            # Check if it looks like a Teams webhook
            valid_domains = ['webhook.office.com', 'outlook.office.com', 'outlook.office365.com']
            if not any(domain in self.teams_webhook for domain in valid_domains):
                self.logger.warning(f"⚠️ URL doesn't appear to be a Teams webhook. Expected domains: {valid_domains}")
                
            response = requests.post(
                self.teams_webhook,
                headers={'Content-Type': 'application/json'},
                json=test_message,
                timeout=10
            )
            
            self.logger.debug(f"🔍 DEBUG: Test response status: {response.status_code}")
            self.logger.debug(f"🔍 DEBUG: Test response text: {response.text}")
            
            if response.status_code == 200:
                self.logger.info("✅ Teams webhook test successful!")
                return True
            elif response.status_code == 405:
                self.logger.error("❌ Webhook test failed with 405 Method Not Allowed")
                self.logger.error("🔧 Common causes:")
                self.logger.error("   • Webhook URL is incorrect or malformed")
                self.logger.error("   • Webhook was created for wrong connector type")
                self.logger.error("   • Webhook has been disabled or expired")
                self.logger.error("   • URL was copied incorrectly (missing parts)")
                return False
            elif response.status_code == 400:
                self.logger.error("❌ Webhook test failed with 400 Bad Request")
                self.logger.error("🔧 This usually means the message format is invalid")
                return False
            elif response.status_code == 404:
                self.logger.error("❌ Webhook test failed with 404 Not Found")
                self.logger.error("🔧 The webhook URL doesn't exist or has been deleted")
                return False
            else:
                self.logger.error(f"❌ Webhook test failed with status {response.status_code}")
                return False
                
        except requests.exceptions.Timeout:
            self.logger.error("❌ Webhook test timed out")
            return False
        except requests.exceptions.ConnectionError:
            self.logger.error("❌ Cannot connect to webhook URL")
            return False
        except Exception as e:
            self.logger.error(f"❌ Webhook test error: {e}")
            return False

    async def send_teams_notification(self, analysis_result: Dict) -> bool:
        """
        Send notification to MS Teams with comprehensive debugging
        
        Args:
            analysis_result: Analysis results from AI
            
        Returns:
            Success status
        """
        self.logger.debug("🔍 DEBUG: Starting Teams notification process")
        self.logger.debug(f"🔍 DEBUG: Analysis result keys: {list(analysis_result.keys())}")
        
        if not self.teams_webhook:
            self.logger.warning("⚠️ MS Teams webhook URL not configured")
            self.logger.debug("🔍 DEBUG: Teams webhook URL is empty or None")
            return False
        
        self.logger.debug(f"🔍 DEBUG: Teams webhook URL configured: {self.teams_webhook[:50]}...")
            
        # Extract log type from metadata
        log_type = analysis_result.get('metadata', {}).get('log_type', 'unknown')
        self.logger.debug(f"🔍 DEBUG: Extracted log type: {log_type}")
        
        if analysis_result['status'] != 'success':
            self.logger.debug(f"🔍 DEBUG: Analysis failed, sending error notification")
            return await self._send_error_notification(analysis_result, log_type)
            
        analysis = analysis_result['analysis']
        severity = analysis.get('severity', 'UNKNOWN')
        
        self.logger.debug(f"🔍 DEBUG: Analysis severity: {severity}")
        self.logger.debug(f"🔍 DEBUG: Analysis keys: {list(analysis.keys())}")
        
        # Choose color based on severity
        color_map = {
            'CRITICAL': 'FF0000',  # Red
            'HIGH': 'FF8C00',      # Orange
            'MEDIUM': 'FFD700',    # Yellow
            'LOW': '32CD32'        # Green
        }
        
        color = color_map.get(severity, 'Gray')
        self.logger.debug(f"🔍 DEBUG: Selected color for severity '{severity}': {color}")
        
        # Create Teams message card
        teams_message = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": f"{severity} Issues Detected in {log_type.title()} Logs",
            "themeColor": color,
            "sections": [
                {
                    "activityTitle": f"🚨 AI Log Analysis Alert - {severity}",
                    "activitySubtitle": f"{log_type.title()} Logs Analysis",
                    "activityImage": "https://raw.githubusercontent.com/microsoft/vscode-icons/main/icons/file_type_log.svg",
                    "facts": [
                        {"name": "Log Type", "value": log_type.title()},
                        {"name": "Severity", "value": severity},
                        {"name": "Analysis Time", "value": analysis_result['metadata']['analysis_time']},
                        {"name": "Log Lines Analyzed", "value": str(analysis_result['metadata']['log_lines'])}
                    ],
                    "text": analysis.get('summary', 'Log analysis completed')
                }
            ]
        }
        
        self.logger.debug(f"🔍 DEBUG: Base Teams message created with {len(teams_message['sections'])} sections")
        
        # Add error patterns section
        if analysis.get('error_patterns'):
            error_patterns = analysis['error_patterns'][:3]  # Show top 3
            self.logger.debug(f"🔍 DEBUG: Adding {len(error_patterns)} error patterns to Teams message")
            
            error_text = "\n".join([
                f"• **{pattern['type']}**: {pattern['count']} occurrences ({pattern['severity']})"
                for pattern in error_patterns
            ])
            teams_message["sections"].append({
                "activityTitle": "🔍 Error Patterns Detected",
                "text": error_text
            })
            self.logger.debug(f"🔍 DEBUG: Error patterns text: {error_text[:100]}...")
            
        # Add immediate actions section
        if analysis.get('immediate_actions'):
            immediate_actions = analysis['immediate_actions'][:3]  # Show top 3
            self.logger.debug(f"🔍 DEBUG: Adding {len(immediate_actions)} immediate actions to Teams message")
            
            action_text = "\n".join([
                f"• **{action['priority']}**: {action['action']} (ETA: {action.get('estimated_time', 'Unknown')})"
                for action in immediate_actions
            ])
            teams_message["sections"].append({
                "activityTitle": "⚡ Immediate Actions Required",
                "text": action_text
            })
            self.logger.debug(f"🔍 DEBUG: Actions text: {action_text[:100]}...")
            
        self.logger.debug(f"🔍 DEBUG: Final Teams message has {len(teams_message['sections'])} sections")
        self.logger.debug(f"🔍 DEBUG: Teams message size: {len(str(teams_message))} characters")
        
        try:
            self.logger.debug(f"🔍 DEBUG: Preparing to send POST request to Teams webhook")
            self.logger.debug(f"🔍 DEBUG: Webhook URL: {self.teams_webhook}")
            self.logger.debug(f"🔍 DEBUG: Request headers: {{'Content-Type': 'application/json'}}")
            self.logger.debug(f"🔍 DEBUG: Request timeout: 10 seconds")
            self.logger.debug(f"🔍 DEBUG: Message payload preview: {str(teams_message)[:300]}...")
            
            # Validate webhook URL format
            if not self.teams_webhook.startswith('https://'):
                self.logger.error(f"❌ Invalid webhook URL format: {self.teams_webhook}")
                return False
                
            if 'webhook.office.com' not in self.teams_webhook and 'outlook.office.com' not in self.teams_webhook:
                self.logger.warning(f"⚠️ Webhook URL doesn't appear to be a valid Teams webhook: {self.teams_webhook}")
            
            response = requests.post(
                self.teams_webhook,
                headers={'Content-Type': 'application/json'},
                json=teams_message,
                timeout=10
            )
            
            self.logger.debug(f"🔍 DEBUG: Teams webhook response status: {response.status_code}")
            self.logger.debug(f"🔍 DEBUG: Teams webhook response headers: {dict(response.headers)}")
            self.logger.debug(f"🔍 DEBUG: Teams webhook response text: {response.text}")
            self.logger.debug(f"🔍 DEBUG: Teams webhook response URL: {response.url}")
            
            if response.status_code == 200:
                self.logger.info("✅ MS Teams notification sent successfully")
                self.logger.debug("🔍 DEBUG: Teams notification completed successfully")
                return True
            elif response.status_code == 405:
                self.logger.error(f"❌ Teams webhook returned 405 Method Not Allowed")
                self.logger.error(f"🔍 This usually means:")
                self.logger.error(f"   1. The webhook URL is incorrect or expired")
                self.logger.error(f"   2. The webhook was created for a different connector type")
                self.logger.error(f"   3. The webhook URL was copied incorrectly")
                self.logger.error(f"🔧 Please verify your Teams webhook URL in the .env file")
                return False
            else:
                self.logger.error(f"❌ Teams notification failed: {response.status_code}")
                self.logger.debug(f"🔍 DEBUG: Teams webhook failed with status {response.status_code}")
                self.logger.debug(f"🔍 DEBUG: Full response content: {response.text}")
                return False
                
        except requests.exceptions.Timeout as e:
            self.logger.error(f"❌ Teams notification timeout: {e}")
            self.logger.debug(f"🔍 DEBUG: Request timed out after 10 seconds")
            return False
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"❌ Teams notification connection error: {e}")
            self.logger.debug(f"🔍 DEBUG: Connection error - check webhook URL and network")
            return False
        except requests.exceptions.RequestException as e:
            self.logger.error(f"❌ Teams notification request error: {e}")
            self.logger.debug(f"🔍 DEBUG: General request exception: {type(e).__name__}")
            return False
        except Exception as e:
            self.logger.error(f"❌ Failed to send Teams notification: {e}")
            self.logger.debug(f"🔍 DEBUG: Unexpected error: {type(e).__name__} - {str(e)}")
            return False
            
    async def _send_error_notification(self, analysis_result: Dict, log_type: str) -> bool:
        """Send error notification to Teams with debug logging"""
        self.logger.debug("🔍 DEBUG: Starting error notification to Teams")
        
        if not self.teams_webhook:
            self.logger.debug("🔍 DEBUG: No Teams webhook configured for error notification")
            return False
            
        self.logger.debug(f"🔍 DEBUG: Creating error notification for log type: {log_type}")
        self.logger.debug(f"🔍 DEBUG: Error details: {analysis_result.get('error', 'Unknown error')}")
        
        error_message = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": f"AI Log Analysis Failed for {log_type.title()}",
            "themeColor": "FF0000",
            "sections": [
                {
                    "activityTitle": "❌ AI Log Analysis Error",
                    "activitySubtitle": f"{log_type.title()} Logs",
                    "facts": [
                        {"name": "Log Type", "value": log_type.title()},
                        {"name": "Error", "value": analysis_result.get('error', 'Unknown error')},
                        {"name": "Timestamp", "value": datetime.utcnow().isoformat()}
                    ],
                    "text": "The AI log analysis process encountered an error and could not complete successfully."
                }
            ]
        }
        
        self.logger.debug(f"🔍 DEBUG: Error message payload size: {len(str(error_message))} characters")
        
        try:
            self.logger.debug("🔍 DEBUG: Sending error notification to Teams webhook")
            self.logger.debug(f"🔍 DEBUG: Error webhook URL: {self.teams_webhook}")
            
            response = requests.post(
                self.teams_webhook, 
                json=error_message, 
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            self.logger.debug(f"🔍 DEBUG: Error notification response status: {response.status_code}")
            self.logger.debug(f"🔍 DEBUG: Error notification response: {response.text}")
            
            success = response.status_code == 200
            if success:
                self.logger.debug("🔍 DEBUG: Error notification sent successfully")
            elif response.status_code == 405:
                self.logger.error(f"❌ Error notification webhook returned 405 Method Not Allowed")
                self.logger.error(f"🔧 Please check your Teams webhook URL configuration")
            else:
                self.logger.debug(f"🔍 DEBUG: Error notification failed with status {response.status_code}")
                
            return success
        except Exception as e:
            self.logger.error(f"❌ Failed to send error notification: {e}")
            self.logger.debug(f"🔍 DEBUG: Exception in error notification: {type(e).__name__} - {str(e)}")
            return False
            
    async def run_analysis(self) -> Dict:
        """
        Main method to run complete log analysis workflow with random selection
        
        Returns:
            Complete analysis results
        """
        start_time = datetime.utcnow()
        
        # Randomly select log type and severity
        log_type = random.choice(list(self.log_types.keys()))
        severity = random.choice(self.severity_levels)
        
        self.logger.info(f"🚀 Starting AI Log Analysis for {log_type} ({severity}) - RANDOM SELECTION")
        
        try:
            # Step 1: Generate synthetic logs and save to file
            log_file_path = await self.generate_synthetic_logs(log_type, severity)
            
            # Step 2: Analyze logs from file with AI
            analysis_result = await self.analyze_logs_with_ai(log_file_path)
            
            # Step 3: Send Teams notification
            notification_sent = await self.send_teams_notification(analysis_result)
            
            # Compile final result
            end_time = datetime.utcnow()
            total_time = (end_time - start_time).total_seconds()
            
            final_result = {
                'workflow_status': 'completed',
                'log_type': log_type,
                'severity': severity,
                'log_file_path': log_file_path,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'total_time_seconds': round(total_time, 2),
                'analysis_result': analysis_result,
                'teams_notification_sent': notification_sent
            }
            
            self.logger.info(f"✅ Analysis workflow completed in {total_time:.2f} seconds")
            return final_result
            
        except Exception as e:
            self.logger.error(f"❌ Analysis workflow failed: {e}")
            return {
                'workflow_status': 'failed',
                'log_type': log_type if 'log_type' in locals() else 'unknown',
                'severity': severity if 'severity' in locals() else 'unknown',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }

# Interactive CLI
async def main():
    """Simplified command-line interface with random log generation"""
    print("🔍 AI Log Analyzer - Random Log Generator & Analyzer")
    print("=" * 60)
    
    analyzer = AILogAnalyzer()
    
    print(f"\n📁 Log files will be saved to: {analyzer.log_dir}")
    print(f"🎲 Randomly selecting from: {list(analyzer.log_types.keys())}")
    print(f"🎲 Severity levels: {analyzer.severity_levels}")
    
    # Test Teams webhook if configured
    if analyzer.teams_webhook:
        print(f"\n🧪 Testing Teams webhook configuration...")
        webhook_test = await analyzer.test_teams_webhook()
        if not webhook_test:
            print("\n⚠️ Teams webhook test failed! Check your configuration.")
            print("💡 You can still proceed, but Teams notifications won't work.")
            proceed = input("\nContinue anyway? (y/N): ").strip().lower()
            if proceed not in ['y', 'yes']:
                print("❌ Cancelled by user.")
                return
        else:
            print("✅ Teams webhook is working correctly!")
    else:
        print("\n⚠️ Teams webhook not configured (optional)")
    
    # Ask user if they want to proceed
    proceed = input(f"\n🚀 Ready to generate and analyze random logs? (y/N): ").strip().lower()
    if proceed not in ['y', 'yes']:
        print("❌ Cancelled by user.")
        return
    
    print(f"\n🚀 Starting random log analysis...")
    print("=" * 60)
    
    # Run analysis with random selection
    result = await analyzer.run_analysis()
    
    # Display results
    print(f"\n📊 Analysis Results:")
    print(f"Log Type: {result.get('log_type', 'N/A')}")
    print(f"Severity: {result.get('severity', 'N/A')}")
    print(f"Log File: {result.get('log_file_path', 'N/A')}")
    
    if result['workflow_status'] == 'completed':
        analysis = result['analysis_result']
        if analysis['status'] == 'success':
            ai_analysis = analysis['analysis']
            print(f"AI Severity Assessment: {ai_analysis.get('severity', 'N/A')}")
            print(f"Summary: {ai_analysis.get('summary', 'N/A')}")
            print(f"Teams Notification: {'✅ Sent' if result['teams_notification_sent'] else '❌ Failed'}")
            
            # Show error patterns if any
            error_patterns = ai_analysis.get('error_patterns', [])
            if error_patterns:
                print(f"\n🔍 Top Error Patterns:")
                for i, pattern in enumerate(error_patterns[:3], 1):
                    print(f"  {i}. {pattern.get('type', 'Unknown')}: {pattern.get('count', 0)} occurrences")
                    
            # Show immediate actions if any
            actions = ai_analysis.get('immediate_actions', [])
            if actions:
                print(f"\n⚡ Immediate Actions:")
                for i, action in enumerate(actions[:3], 1):
                    print(f"  {i}. [{action.get('priority', 'UNKNOWN')}] {action.get('action', 'No action specified')}")
        else:
            print(f"\n❌ Analysis failed: {analysis.get('error', 'Unknown error')}")
    else:
        print(f"\n❌ Workflow failed: {result.get('error', 'Unknown error')}")
    
    print(f"\nTotal time: {result.get('total_time_seconds', 0):.2f} seconds")
    print(f"📁 Generated log file available at: {result.get('log_file_path', 'N/A')}")

# Webhook testing utility
async def test_webhook():
    """Standalone webhook testing function"""
    print("🧪 Teams Webhook Tester")
    print("=" * 30)
    
    analyzer = AILogAnalyzer()
    result = await analyzer.test_teams_webhook()
    
    if result:
        print("\n✅ Webhook test successful! Check your Teams channel for the test message.")
    else:
        print("\n❌ Webhook test failed. Please check your configuration.")
        print("\n🔧 Troubleshooting steps:")
        print("1. Verify your Teams webhook URL in the .env file")
        print("2. Make sure the webhook hasn't expired")
        print("3. Check that the connector is still active in Teams")
        print("4. Ensure the URL is complete and not truncated")

if __name__ == "__main__":
    # Environment variables can be set in .env file:
    # OPENAI_API_KEY=your-openai-api-key
    # TEAMS_WEBHOOK_URL=your-teams-webhook-url
    # LOG_DIR=./generated_logs (optional, defaults to ./generated_logs)
    # LOG_LEVEL=DEBUG (for detailed webhook debugging)
    
    import sys
    
    # Check if user wants to test webhook only
    if len(sys.argv) > 1 and sys.argv[1] == 'test-webhook':
        asyncio.run(test_webhook())
    else:
        asyncio.run(main())
