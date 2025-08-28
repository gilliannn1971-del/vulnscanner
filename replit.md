# Educational Vulnerability Scanner

## Overview

This is an educational web vulnerability scanner built with Streamlit that helps users understand common web security vulnerabilities. The application performs automated scans for SQL injection, Cross-Site Scripting (XSS), and Insecure Direct Object Reference (IDOR) vulnerabilities, while providing detailed explanations and prevention methods. The scanner is designed for learning purposes and includes comprehensive reporting features with both JSON and HTML output formats. Additionally, it features an automated remediation system that can attempt to fix detected vulnerabilities based on severity levels, and an interactive attack engine that automatically exploits found vulnerabilities with real-time console output and user interaction capabilities.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: Streamlit web application framework for rapid UI development
- **User Interface**: Single-page application with sidebar configuration and main scanning interface
- **State Management**: Streamlit session state for maintaining scan results and scanning status
- **Layout**: Wide layout with column-based organization for optimal user experience

### Backend Architecture
- **Core Scanner**: Object-oriented design with `VulnerabilityScanner` class handling all scanning operations
- **Vulnerability Detection**: Modular approach with separate methods for different vulnerability types (SQL injection, XSS, IDOR)
- **Report Generation**: Dedicated `ReportGenerator` class for creating JSON and HTML reports
- **Knowledge Base**: `VulnerabilityDatabase` class containing prevention methods and educational content
- **Auto-Remediation System**: `AutoRemediation` class that provides automated vulnerability fixing capabilities with severity-based filtering
- **Interactive Attack Engine**: `AttackEngine` class that automatically exploits discovered vulnerabilities with real-time console output and data extraction

### Data Storage Solutions
- **In-Memory Storage**: Uses Python dictionaries and lists for storing scan results during execution
- **Session State**: Streamlit's built-in session state for persisting data across user interactions
- **File Export**: Generates downloadable reports in JSON and HTML formats

### Security and Ethical Considerations
- **Responsible Scanning**: Built-in warnings about only scanning owned or permitted websites
- **Rate Limiting**: Includes delays between requests to prevent overwhelming target servers
- **User-Agent Identification**: Uses identifiable User-Agent header for transparency
- **Educational Focus**: Designed for learning rather than exploitation

### Core Components
- **Form Discovery**: Automatically identifies and analyzes web forms for potential vulnerabilities
- **HTTP Analysis**: Examines HTTP responses, headers, and security configurations
- **Content Parsing**: Uses BeautifulSoup for HTML parsing and analysis
- **Security Headers Check**: Evaluates presence and configuration of security headers
- **Auto-Remediation Engine**: Automatically attempts to fix detected vulnerabilities based on severity levels
- **Fix Verification**: Validates and reports on the success of automated remediation attempts
- **Interactive Attack Engine**: Automatically exploits found vulnerabilities with real-time attack execution
- **Attack Console**: Real-time console output showing attack progress and results
- **Data Extraction**: Automatically extracts sensitive data during successful exploits
- **Credential Discovery**: Identifies and extracts user credentials through various attack vectors

## External Dependencies

### Python Libraries
- **streamlit**: Web application framework for creating the user interface
- **pandas**: Data manipulation and analysis for handling scan results
- **requests**: HTTP library for making web requests and scanning operations
- **beautifulsoup4**: HTML and XML parser for analyzing web page content
- **urllib**: URL parsing and manipulation utilities

### Web Technologies
- **HTTP/HTTPS**: Primary protocol for communicating with target websites
- **HTML Parsing**: Analyzes HTML content to identify forms and potential vulnerabilities
- **CSS/JavaScript**: Minimal frontend dependencies handled through Streamlit

### Browser Compatibility
- **Modern Web Browsers**: Compatible with Chrome, Firefox, Safari, and Edge through Streamlit's web interface
- **Responsive Design**: Streamlit's built-in responsive capabilities for various screen sizes