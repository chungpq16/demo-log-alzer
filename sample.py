# cloudwatch_ai_analyzer.py
import asyncio
import boto3
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from botocore.exceptions import ClientError, NoCredentialsError

class CloudWatchAILogAnalyzer:
    """Production-ready AI-powered CloudWatch log analysis system"""
  
    def __init__(self, aws_region: str = 'us-east-1'):
        self.ai_client = UnifiedAIClient()
        self.aws_region = aws_region
        self.setup_logging()
        self.setup_aws_clients()
  
        # Alert thresholds - customize based on your needs
        self.alert_config = {
            'critical_error_threshold': 5,  # errors per minute
            'warning_threshold': 10,        # warnings per minute  
            'response_time_threshold': 2000  # milliseconds
        }
  
    def setup_logging(self):
        """Configure logging for debugging and monitoring"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ai_log_analyzer.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
  
    def setup_aws_clients(self):
        """Initialize AWS clients with proper error handling"""
        try:
            self.cloudwatch_logs = boto3.client('logs', region_name=self.aws_region)
            self.logger.info(f"✅ AWS CloudWatch client initialized for region: {self.aws_region}")
        except NoCredentialsError:
            self.logger.error("❌ AWS credentials not found. Run 'aws configure' first.")
            raise
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize AWS clients: {e}")
            raise
  
    # STEP 1: REAL CLOUDWATCH LOG COLLECTION
    async def collect_logs_from_cloudwatch(
        self, 
        log_group_name: str, 
        time_window_minutes: int = 10,
        filter_pattern: str = "",
        max_events: int = 1000
    ) -> str:
        """
        🔍 STEP 1: Collect logs from AWS CloudWatch
  
        Implementation steps:
        1.1 Calculate time range for collection
        1.2 Find relevant log streams
        1.3 Fetch log events from streams  
        1.4 Format logs for AI analysis
        """
        self.logger.info(f"🔍 Collecting logs from CloudWatch group: {log_group_name}")
  
        # Step 1.1: Calculate time range (CloudWatch uses milliseconds)
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=time_window_minutes)
        start_time_ms = int(start_time.timestamp() * 1000)
        end_time_ms = int(end_time.timestamp() * 1000)
  
        self.logger.info(f"📅 Time range: {start_time} to {end_time}")
  
        try:
            # Step 1.2: Get log streams that have data in our time range
            log_streams = await self._get_active_log_streams(
                log_group_name, start_time_ms, end_time_ms
            )
  
            if not log_streams:
                self.logger.warning(f"⚠️ No active log streams found for: {log_group_name}")
                return ""
  
            # Step 1.3: Collect events from multiple streams
            all_log_events = []
            for stream in log_streams[:5]:  # Limit to 5 streams to avoid overwhelming AI
                stream_name = stream['logStreamName']
                self.logger.info(f"📄 Processing stream: {stream_name}")
      
                events = await self._fetch_log_events(
                    log_group_name, stream_name, start_time_ms, end_time_ms,
                    filter_pattern, max_events
                )
                all_log_events.extend(events)
  
            # Step 1.4: Format for AI consumption
            formatted_logs = self._format_cloudwatch_logs(all_log_events)
  
            self.logger.info(f"✅ Collected {len(all_log_events)} events ({len(formatted_logs)} chars)")
            return formatted_logs
  
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ResourceNotFoundException':
                self.logger.error(f"❌ Log group not found: {log_group_name}")
            elif error_code == 'AccessDeniedException':
                self.logger.error(f"❌ Access denied to: {log_group_name}")
            else:
                self.logger.error(f"❌ AWS error: {error_code} - {e}")
            raise
        except Exception as e:
            self.logger.error(f"❌ CloudWatch collection failed: {e}")
            raise
  
    async def _get_active_log_streams(
        self, log_group_name: str, start_time_ms: int, end_time_ms: int
    ) -> List[Dict]:
        """Find log streams with events in the specified time range"""
        try:
            response = self.cloudwatch_logs.describe_log_streams(
                logGroupName=log_group_name,
                orderBy='LastEventTime',
                descending=True,
                limit=10  # Get 10 most recent streams
            )
  
            # Filter streams that overlap with our time window
            active_streams = []
            for stream in response['logStreams']:
                last_event = stream.get('lastEventTime', 0)
                first_event = stream.get('firstEventTime', 0)
      
                # Check if stream has events in our time range
                if (last_event >= start_time_ms and first_event <= end_time_ms):
                    active_streams.append(stream)
  
            return active_streams
  
        except Exception as e:
            self.logger.error(f"Failed to get log streams: {e}")
            return []
  
    async def _fetch_log_events(
        self, 
        log_group_name: str, 
        log_stream_name: str, 
        start_time_ms: int, 
        end_time_ms: int,
        filter_pattern: str,
        max_events: int
    ) -> List[Dict]:
        """Fetch log events from a specific CloudWatch stream"""
        try:
            params = {
                'logGroupName': log_group_name,
                'logStreamNames': [log_stream_name],
                'startTime': start_time_ms,
                'endTime': end_time_ms,
                'limit': min(max_events, 1000)  # CloudWatch max is 10k, but we limit for AI
            }
  
            # Add filter if specified (e.g., "ERROR" or "[timestamp, request_id, ERROR]")
            if filter_pattern:
                params['filterPattern'] = filter_pattern
  
            response = self.cloudwatch_logs.filter_log_events(**params)
            return response.get('events', [])
  
        except Exception as e:
            self.logger.error(f"Failed to fetch events from {log_stream_name}: {e}")
            return []
  
    def _format_cloudwatch_logs(self, log_events: List[Dict]) -> str:
        """Format CloudWatch events into readable text for AI analysis"""
        if not log_events:
            return ""
  
        # Sort chronologically 
        sorted_events = sorted(log_events, key=lambda x: x['timestamp'])
  
        formatted_lines = []
        for event in sorted_events:
            # Convert CloudWatch timestamp to readable format
            timestamp = datetime.fromtimestamp(event['timestamp'] / 1000)
            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
  
            # Clean the log message
            message = event['message'].strip()
            log_line = f"{timestamp_str} {message}"
            formatted_lines.append(log_line)
  
        return '\n'.join(formatted_lines)
  
    # STEP 2: ENHANCED AI ANALYSIS  
    async def analyze_logs_with_ai(
        self, log_content: str, service_name: str, log_group_name: str
    ) -> Dict:
        """
        🤖 STEP 2: AI Analysis of CloudWatch logs
  
        Implementation steps:
        2.1 Validate log content
        2.2 Create CloudWatch-optimized prompt
        2.3 Send to AI model
        2.4 Parse and validate response
        2.5 Return structured analysis
        """
        self.logger.info(f"🤖 Starting AI analysis for {service_name}")
  
        # Step 2.1: Input validation
        if not log_content.strip():
            return {
                'status': 'error',
                'error': 'No log content to analyze',
                'service': service_name
            }
  
        # Step 2.2: CloudWatch-optimized prompt
        prompt = f"""
Analyze these AWS CloudWatch logs and provide structured insights:

SERVICE: {service_name}
LOG GROUP: {log_group_name}
TIMEFRAME: Last 10 minutes

LOGS:
{log_content}

Return analysis as valid JSON:
{{
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "summary": "One sentence summary of main issues",
    "error_patterns": [
        {{"type": "error_type", "count": "number", "severity": "level", "sample": "example_message"}}
    ],
    "performance_issues": [
        {{"issue": "description", "metric": "value", "threshold": "expected"}}
    ],
    "aws_specific_issues": [
        {{"service": "aws_service_name", "issue": "problem", "action": "recommendation"}}
    ],
    "immediate_actions": [
        {{"action": "what_to_do", "priority": "HIGH|MED|LOW", "time": "estimate"}}
    ],
    "root_causes": [
        {{"cause": "likely_reason", "confidence": "percentage"}}
    ]
}}

Focus on: AWS service errors, timeouts, resource limits, API throttling, database issues.
"""
  
        try:
            # Step 2.3: Send to AI with optimized settings
            request = AIRequest(
                prompt=prompt,
                model='gpt-4',
                provider='openai',
                max_tokens=1500,
                temperature=0.1  # Low temperature for consistent analysis
            )
  
            start_time = time.time()
            response = await self.ai_client.generate(request)
            analysis_time = time.time() - start_time
  
            # Step 2.4: Parse response
            try:
                analysis = json.loads(response.content)
      
                # Step 2.5: Return with metadata
                return {
                    'status': 'success',
                    'analysis': analysis,
                    'metadata': {
                        'service': service_name,
                        'log_group': log_group_name,
                        'analysis_time': round(analysis_time, 2),
                        'tokens_used': response.tokens_used,
                        'cost': round(response.cost, 4),
                        'model': response.model,
                        'log_size_chars': len(log_content)
                    }
                }
            except json.JSONDecodeError as e:
                self.logger.error(f"❌ AI returned invalid JSON: {e}")
                return {
                    'status': 'error',
                    'error': f'AI response parsing failed: {e}',
                    'raw_response': response.content[:500] + "..." if len(response.content) > 500 else response.content
                }
      
        except Exception as e:
            self.logger.error(f"❌ AI analysis failed: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }

    # STEP 3: ALERT GENERATION
    async def generate_alerts(self, analysis: Dict, service_name: str) -> List[Dict]:
        """Generate alerts based on AI analysis"""
        alerts = []
  
        if analysis['status'] != 'success':
            # If AI analysis failed, create a system alert
            alerts.append({
                'type': 'SYSTEM_ERROR',
                'severity': 'HIGH',
                'message': f'AI log analysis failed for {service_name}',
                'details': analysis.get('error', 'Unknown error'),
                'timestamp': datetime.utcnow().isoformat(),
                'service': service_name
            })
            return alerts
  
        ai_analysis = analysis['analysis']
  
        # Generate alerts based on severity
        if ai_analysis.get('severity') in ['CRITICAL', 'HIGH']:
            alerts.append({
                'type': 'SERVICE_ISSUE',
                'severity': ai_analysis['severity'],
                'message': f"{service_name}: {ai_analysis.get('summary', 'Critical issues detected')}",
                'details': {
                    'error_patterns': ai_analysis.get('error_patterns', []),
                    'immediate_actions': ai_analysis.get('immediate_actions', []),
                    'root_causes': ai_analysis.get('root_causes', [])
                },
                'timestamp': datetime.utcnow().isoformat(),
                'service': service_name,
                'ai_metadata': analysis.get('metadata', {})
            })
  
        # Check performance thresholds
        performance_issues = ai_analysis.get('performance_issues', [])
        for issue in performance_issues:
            alerts.append({
                'type': 'PERFORMANCE_ISSUE',
                'severity': 'MEDIUM',
                'message': f"{service_name}: Performance issue detected",
                'details': issue,
                'timestamp': datetime.utcnow().isoformat(),
                'service': service_name
            })
  
        self.logger.info(f"Generated {len(alerts)} alerts for {service_name}")
        return alerts
  
    # Step 4: Alert Delivery
    async def send_alerts(self, alerts: List[Dict]) -> bool:
        """Send alerts to appropriate channels"""
        if not alerts:
            self.logger.info("No alerts to send")
            return True
  
        try:
            for alert in alerts:
                # In production, integrate with:
                # - Slack/Teams webhooks
                # - PagerDuty API
                # - Email notifications
                # - JIRA ticket creation
                # - Custom dashboards
  
                await self._send_to_slack(alert)
                await self._send_to_monitoring_system(alert)
  
                self.logger.info(f"Alert sent: {alert['type']} - {alert['severity']}")
  
            return True
  
        except Exception as e:
            self.logger.error(f"Failed to send alerts: {e}")
            return False
  
    async def _send_to_slack(self, alert: Dict):
        """Send alert to Slack (simulated)"""
        # In production: use Slack webhooks or SDK
        slack_message = {
            'text': f"🚨 {alert['severity']} Alert",
            'attachments': [{
                'color': 'danger' if alert['severity'] in ['CRITICAL', 'HIGH'] else 'warning',
                'fields': [
                    {'title': 'Service', 'value': alert['service'], 'short': True},
                    {'title': 'Type', 'value': alert['type'], 'short': True},
                    {'title': 'Message', 'value': alert['message'], 'short': False}
                ]
            }]
        }
  
        # Simulate API call
        await asyncio.sleep(0.1)
        self.logger.info(f"Slack alert sent: {alert['message'][:50]}...")
  
    async def _send_to_monitoring_system(self, alert: Dict):
        """Send to monitoring system (simulated)"""
        # In production: integrate with Prometheus, Grafana, DataDog, etc.
        await asyncio.sleep(0.1)
        self.logger.info(f"Monitoring system updated with alert: {alert['type']}")
  
    # Main CloudWatch Analysis Method
    async def analyze_logs(
        self, 
        log_group_name: str, 
        time_range_hours: int = 1, 
        filter_pattern: str = "",
        max_events: int = 1000
    ) -> Dict:
        """
        🎯 Main method: Complete CloudWatch log analysis workflow
  
        Args:
            log_group_name: AWS CloudWatch log group (e.g., '/aws/lambda/my-function')
            time_range_hours: How many hours back to analyze (default: 1)
            filter_pattern: CloudWatch filter pattern (optional)
            max_events: Maximum number of log events to analyze
        """
        workflow_start = time.time()
        service_name = log_group_name.split('/')[-1]  # Extract service name from log group
  
        self.logger.info(f"🚀 Starting CloudWatch analysis for: {log_group_name}")

        try:
            # Step 1: Collect logs from CloudWatch
            time_window_minutes = time_range_hours * 60
            logs = await self.collect_logs_from_cloudwatch(
                log_group_name=log_group_name,
                time_window_minutes=time_window_minutes,
                filter_pattern=filter_pattern,
                max_events=max_events
            )
  
            if not logs:
                return {
                    'status': 'no_data',
                    'message': f'No logs found in {log_group_name} for the last {time_range_hours} hours',
                    'log_group': log_group_name,
                    'time_range_hours': time_range_hours,
                    'timestamp': datetime.utcnow().isoformat()
                }
  
            # Step 2: AI analysis
            analysis = await self.analyze_logs_with_ai(logs, service_name, log_group_name)
  
            # Step 3: Generate alerts
            alerts = await self.generate_alerts(analysis, service_name)
  
            # Step 4: Send alerts
            alert_success = await self.send_alerts(alerts)
  
            workflow_time = time.time() - workflow_start
  
            result = {
                'status': 'completed',
                'log_group': log_group_name,
                'service': service_name,
                'time_range_hours': time_range_hours,
                'workflow_time': round(workflow_time, 2),
                'logs_size_chars': len(logs),
                'analysis_result': analysis,
                'alerts_generated': len(alerts),
                'alerts_sent': alert_success,
                'timestamp': datetime.utcnow().isoformat()
            }
  
            self.logger.info(f"✅ CloudWatch analysis completed for {service_name} in {workflow_time:.2f}s")
            return result
  
        except Exception as e:
            self.logger.error(f"❌ CloudWatch analysis workflow failed: {e}")
            return {
                'status': 'failed',
                'log_group': log_group_name,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }

# Usage Example
async def main():
    """Example usage of the CloudWatch AI Log Analyzer"""
    analyzer = CloudWatchAILogAnalyzer()
  
    # Analyze CloudWatch logs for a web service
    result = await analyzer.analyze_logs(
        log_group_name='/aws/lambda/web-api',
        time_range_hours=1,  # Analyze last 1 hour
        filter_pattern='ERROR'  # Only look at error logs
    )
  
    print("Analysis Result:")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    asyncio.run(main())