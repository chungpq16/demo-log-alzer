# AI Log Analyzer - Product Requirements Document

## Summary

The AI Log Analyzer is a production-ready Python script that automates log analysis using AI with intelligent random log generation and MS Teams integration.

### Key Features:
- **Random Log Generator** using OpenAI GPT-3.5 Turbo to generate 15 lines of CRITICAL or HIGH severity error logs from multiple log types:
    - Nginx web server logs
    - Java application logs  
    - CI/CD pipeline logs
    - System/OS logs
    - Kubernetes cluster logs
    - Only generates 1 type of log per execution (single log file, not mixed)
- **AI-powered analysis** using GPT-4 to identify patterns, errors, and performance issues
- **Intelligent alerting** with automatic severity assessment and structured insights
- **MS Teams notifications** via incoming webhook with rich message cards
- **Structured output** with JSON-formatted insights and actionable recommendations
- **File-based workflow** with organized log storage and timestamped files

### Core Workflow:
1. **Random Selection**: Automatically selects log type and severity level
2. **Log Generation**: Creates realistic synthetic logs using OpenAI GPT-3.5
3. **File Storage**: Saves generated logs to organized directory structure
4. **AI Analysis**: Analyzes logs using GPT-4 for comprehensive insights
5. **Teams Notification**: Sends rich notifications with analysis results
6. **Results Display**: Shows complete analysis summary and file locations

### Use Cases:
- **Synthetic Log Testing**: Generate realistic log data for testing and training purposes
- **AI-powered Log Analysis**: Automated pattern recognition and error detection
- **Team Collaboration**: Instant notifications to MS Teams channels for incident response
- **Performance Monitoring**: Intelligent analysis of system performance indicators
- **Educational & Demo**: Perfect for learning AI integration and log analysis workflows

## Technical Architecture

### Simple Architecture Flow:

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│                     │    │                     │    │                     │
│   Log Generator     │───▶│   Log Analysis      │───▶│   MS Teams          │
│                     │    │                     │    │                     │
│ • Random Selection  │    │ • AI Analysis       │    │ • Rich Notifications│
│ • OpenAI GPT-3.5    │    │ • OpenAI GPT-4      │    │ • Webhook Messages  │
│ • 5 Log Types       │    │ • Pattern Detection │    │ • Color-Coded       │
│ • CRITICAL/HIGH     │    │ • Root Cause        │    │ • Action Items      │
│ • File Storage      │    │ • Recommendations   │    │ • Error Alerts      │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
```

### Data Flow:
1. **Input**: Random log type + severity selection
2. **Generation**: 15 lines of realistic synthetic logs
3. **Storage**: Timestamped files in organized directories
4. **Analysis**: AI-powered pattern recognition and insights
5. **Notification**: Rich Teams messages with actionable alerts
6. **Output**: Console summary + persistent log files

### Core Components:

#### 1. **AILogAnalyzer Class**
- **Environment Management**: Loads configuration from `.env` files
- **Logging Setup**: Configures INFO-level logging to file and console
- **OpenAI Integration**: Manages API connections for both log generation and analysis

#### 2. **Log Generation Engine**
- **Model**: OpenAI GPT-3.5 Turbo
- **Input**: Specialized prompts for each log type with severity specifications
- **Output**: 15 lines of realistic, properly formatted log entries
- **Storage**: Timestamped files in organized directory structure

#### 3. **AI Analysis Engine**
- **Model**: OpenAI GPT-4 for advanced analysis capabilities
- **Input**: Raw log content from generated files
- **Processing**: Structured JSON analysis with multiple insight categories
- **Output**: Comprehensive analysis including patterns, actions, and root causes

#### 4. **Notification System**
- **Platform**: Microsoft Teams via incoming webhooks
- **Format**: Rich MessageCard format with color-coded severity
- **Content**: Analysis summary, error patterns, and immediate actions
- **Error Handling**: Graceful fallback with detailed error notifications

### Data Flow:

```
1. [Random Selection] → Log Type + Severity
2. [OpenAI GPT-3.5] → Synthetic Log Generation  
3. [File System] → Timestamped Log Storage
4. [File Reader] → Log Content Retrieval
5. [OpenAI GPT-4] → Comprehensive Analysis
6. [Teams Webhook] → Rich Notification
7. [Console Output] → Results Summary
```

### File Structure:
```
generated_logs/
├── nginx_CRITICAL_20250731_143022.log
├── java_HIGH_20250731_143045.log
└── kubernetes_CRITICAL_20250731_143101.log
```

### Configuration:
- **Environment Variables**: `.env` file for API keys and webhook URLs
- **Log Levels**: INFO-level logging for production use
- **Timeouts**: 10-second timeout for HTTP requests
- **Error Handling**: Comprehensive exception handling for all operations

### Dependencies:
- **OpenAI**: `openai==0.28.1` for AI generation and analysis
- **Requests**: `requests==2.31.0` for webhook communications
- **Python-dotenv**: `python-dotenv==1.0.0` for environment management
- **Standard Library**: `asyncio`, `json`, `logging`, `random`, `datetime`