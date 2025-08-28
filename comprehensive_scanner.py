import requests
import socket
import ssl
import dns.resolver
import subprocess
import re
import time
import threading
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Any, Optional
import json
import datetime
from datetime import datetime
try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

# VPS/VDS attacks integrated directly in this scanner

class ComprehensiveScanner:
    """Comprehensive vulnerability scanner for web applications and infrastructure"""

    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        if not self.target_url.startswith(('http://', 'https://')):
            self.target_url = 'https://' + self.target_url

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Educational-Scanner/1.0 (Security Research)'
        })

        self.results = {
            'target_url': self.target_url,
            'target_ip': None,
            'scan_timestamp': datetime.datetime.now().isoformat(),
            'vulnerabilities': [],
            'open_ports': [],
            'services': {},
            'security_headers': [],
            'ssl_info': {},
            'dns_info': {},
            'technologies': [],
            'cms_info': {}
        }

    def check_target_accessibility(self) -> bool:
        """Check if target is accessible"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            if response.status_code == 200:
                # Resolve IP address
                hostname = self.parsed_url.hostname
                if hostname:
                    self.target_ip = socket.gethostbyname(hostname)
                    self.results['target_ip'] = self.target_ip
                return True
        except Exception as e:
            print(f"Target accessibility check failed: {e}")
        return False

    def scan_ports(self, ports: List[int] = None) -> Dict[str, Any]:
        """Scan for open ports"""
        if not ports:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379, 27017]

        open_ports = []
        services = {}

        if not self.target_ip:
            return {'open_ports': [], 'services': {}}

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target_ip, port))

                if result == 0:
                    open_ports.append(port)
                    # Try to identify service
                    service = self._identify_service(port)
                    if service:
                        services[port] = service

                sock.close()
            except Exception:
                continue

        self.results['open_ports'] = open_ports
        self.results['services'] = services
        return {'open_ports': open_ports, 'services': services}

    def _identify_service(self, port: int) -> str:
        """Identify service running on port"""
        service_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        return service_map.get(port, 'Unknown')

    def scan_web_vulnerabilities(self, aggressive: bool = False) -> None:
        """Scan for web application vulnerabilities"""
        # Test SQL Injection
        self._test_sql_injection()

        # Test XSS
        self._test_xss()

        # Test IDOR
        self._test_idor()

        # Test Command Injection
        self._test_command_injection()

        # Test File Inclusion
        self._test_file_inclusion()

        if aggressive:
            # Additional aggressive tests
            self._test_path_traversal()
            self._test_xxe()

    def _test_sql_injection(self) -> None:
        """Test for SQL injection vulnerabilities"""
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users; --",
            "1' UNION SELECT NULL,NULL,NULL--",
            "admin'--",
            "' OR 'a'='a",
            "1' AND SLEEP(5)--"
        ]

        # Test URL parameters
        if '?' in self.target_url:
            base_url, params = self.target_url.split('?', 1)
            param_pairs = params.split('&')

            for payload in payloads:
                for i, param_pair in enumerate(param_pairs):
                    if '=' in param_pair:
                        param_name, param_value = param_pair.split('=', 1)
                        modified_params = param_pairs.copy()
                        modified_params[i] = f"{param_name}={payload}"
                        test_url = f"{base_url}?{'&'.join(modified_params)}"

                        try:
                            response = self.session.get(test_url, timeout=10)
                            if self._detect_sql_error(response.text):
                                self.results['vulnerabilities'].append({
                                    'type': 'SQL Injection',
                                    'severity': 'Critical',
                                    'location': test_url,
                                    'description': f'SQL injection vulnerability detected in parameter {param_name}',
                                    'payload': payload,
                                    'prevention': 'Use parameterized queries and input validation',
                                    'references': ['https://owasp.org/www-community/attacks/SQL_Injection']
                                })
                                break
                        except Exception:
                            continue

    def _detect_sql_error(self, response_text: str) -> bool:
        """Detect SQL error patterns in response"""
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*PostgreSQL",
            r"valid PostgreSQL result",
            r"Oracle error",
            r"Oracle.*ORA-\d+",
            r"Microsoft.*ODBC.*SQL Server",
            r"SQLServer JDBC Driver",
            r"SqlException",
            r"OleDb.OleDbException",
            r"Microsoft JET Database",
            r"Access Database Engine"
        ]

        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def _test_xss(self) -> None:
        """Test for XSS vulnerabilities"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>"
        ]

        # Test URL parameters
        if '?' in self.target_url:
            base_url, params = self.target_url.split('?', 1)
            param_pairs = params.split('&')

            for payload in payloads:
                for i, param_pair in enumerate(param_pairs):
                    if '=' in param_pair:
                        param_name, param_value = param_pair.split('=', 1)
                        modified_params = param_pairs.copy()
                        modified_params[i] = f"{param_name}={payload}"
                        test_url = f"{base_url}?{'&'.join(modified_params)}"

                        try:
                            response = self.session.get(test_url, timeout=10)
                            if payload in response.text:
                                self.results['vulnerabilities'].append({
                                    'type': 'Cross-Site Scripting (XSS)',
                                    'severity': 'High',
                                    'location': test_url,
                                    'description': f'XSS vulnerability detected in parameter {param_name}',
                                    'payload': payload,
                                    'prevention': 'Implement proper input validation and output encoding',
                                    'references': ['https://owasp.org/www-community/attacks/xss/']
                                })
                                break
                        except Exception:
                            continue

    def _test_idor(self) -> None:
        """Test for IDOR vulnerabilities"""
        # Look for numeric IDs in URL
        id_patterns = [
            r'/(\d+)/?$',
            r'[?&]id=(\d+)',
            r'[?&]user_id=(\d+)',
            r'[?&]account=(\d+)'
        ]

        for pattern in id_patterns:
            match = re.search(pattern, self.target_url)
            if match:
                original_id = match.group(1)
                # Test with different IDs
                test_ids = [str(int(original_id) + 1), str(int(original_id) - 1), '1', '0']

                for test_id in test_ids:
                    test_url = re.sub(pattern, lambda m: m.group(0).replace(original_id, test_id), self.target_url)

                    try:
                        response = self.session.get(test_url, timeout=10)
                        if response.status_code == 200 and len(response.text) > 100:
                            self.results['vulnerabilities'].append({
                                'type': 'Insecure Direct Object Reference (IDOR)',
                                'severity': 'High',
                                'location': test_url,
                                'description': f'IDOR vulnerability detected - unauthorized access to object {test_id}',
                                'payload': f'Changed ID from {original_id} to {test_id}',
                                'prevention': 'Implement proper authorization checks for object access',
                                'references': ['https://owasp.org/www-community/Top_10/A01_2021-Broken_Access_Control/']
                            })
                            break
                    except Exception:
                        continue

    def _test_command_injection(self) -> None:
        """Test for command injection vulnerabilities"""
        payloads = [
            "; ls",
            "| whoami",
            "& dir",
            "; cat /etc/passwd",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "; id",
            "&& ping -c 1 127.0.0.1"
        ]

        if '?' in self.target_url:
            base_url, params = self.target_url.split('?', 1)
            param_pairs = params.split('&')

            for payload in payloads:
                for i, param_pair in enumerate(param_pairs):
                    if '=' in param_pair:
                        param_name, param_value = param_pair.split('=', 1)
                        modified_params = param_pairs.copy()
                        modified_params[i] = f"{param_name}={param_value}{payload}"
                        test_url = f"{base_url}?{'&'.join(modified_params)}"

                        try:
                            response = self.session.get(test_url, timeout=10)
                            if self._detect_command_output(response.text):
                                self.results['vulnerabilities'].append({
                                    'type': 'Command Injection',
                                    'severity': 'Critical',
                                    'location': test_url,
                                    'description': f'Command injection vulnerability detected in parameter {param_name}',
                                    'payload': payload,
                                    'prevention': 'Avoid executing system commands with user input; use parameterized commands',
                                    'references': ['https://owasp.org/www-community/attacks/Command_Injection']
                                })
                                break
                        except Exception:
                            continue

    def _detect_command_output(self, response_text: str) -> bool:
        """Detect command execution patterns in response"""
        patterns = [
            r'root:.*:/bin/bash',
            r'uid=\d+.*gid=\d+',
            r'drwx',
            r'total \d+',
            r'Directory of C:\\',
            r'Volume.*Serial Number',
            r'PING.*bytes of data'
        ]

        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def _test_file_inclusion(self) -> None:
        """Test for file inclusion vulnerabilities"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd",
            "file:///etc/passwd",
            "../../../../../etc/passwd%00",
            "....//....//....//etc/passwd"
        ]

        if '?' in self.target_url:
            base_url, params = self.target_url.split('?', 1)
            param_pairs = params.split('&')

            for payload in payloads:
                for i, param_pair in enumerate(param_pairs):
                    if '=' in param_pair:
                        param_name, param_value = param_pair.split('=', 1)
                        modified_params = param_pairs.copy()
                        modified_params[i] = f"{param_name}={payload}"
                        test_url = f"{base_url}?{'&'.join(modified_params)}"

                        try:
                            response = self.session.get(test_url, timeout=10)
                            if self._detect_file_content(response.text):
                                self.results['vulnerabilities'].append({
                                    'type': 'File Inclusion',
                                    'severity': 'High',
                                    'location': test_url,
                                    'description': f'File inclusion vulnerability detected in parameter {param_name}',
                                    'payload': payload,
                                    'prevention': 'Implement proper input validation and use whitelisting for file access',
                                    'references': ['https://owasp.org/www-community/attacks/Path_Traversal']
                                })
                                break
                        except Exception:
                            continue

    def _detect_file_content(self, response_text: str) -> bool:
        """Detect system file content patterns in response"""
        patterns = [
            r'root:x:0:0:root',
            r'daemon:x:1:1:daemon',
            r'# Copyright.*Microsoft Corp',
            r'127\.0\.0\.1.*localhost',
            r'# This file contains the mappings'
        ]

        for pattern in patterns:
            if re.search(pattern, response_text):
                return True
        return False

    def _test_path_traversal(self) -> None:
        """Test for path traversal vulnerabilities"""
        payloads = [
            "../",
            "..\\",
            "....//",
            "....\\\\",
            "%2e%2e%2f",
            "%2e%2e\\",
            "..%2f",
            "..%5c"
        ]

        # Test in URL path
        for payload in payloads:
            test_url = self.target_url + "/" + payload + "etc/passwd"
            try:
                response = self.session.get(test_url, timeout=10)
                if self._detect_file_content(response.text):
                    self.results['vulnerabilities'].append({
                        'type': 'Path Traversal',
                        'severity': 'High',
                        'location': test_url,
                        'description': 'Path traversal vulnerability detected',
                        'payload': payload,
                        'prevention': 'Implement proper input validation and restrict file access',
                        'references': ['https://owasp.org/www-community/attacks/Path_Traversal']
                    })
                    break
            except Exception:
                continue

    def _test_xxe(self) -> None:
        """Test for XXE vulnerabilities"""
        xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]>
<root>&test;</root>'''

        try:
            response = self.session.post(
                self.target_url,
                data=xxe_payload,
                headers={'Content-Type': 'application/xml'},
                timeout=10
            )

            if self._detect_file_content(response.text):
                self.results['vulnerabilities'].append({
                    'type': 'XML External Entity (XXE)',
                    'severity': 'High',
                    'location': self.target_url,
                    'description': 'XXE vulnerability detected',
                    'payload': xxe_payload,
                    'prevention': 'Disable external entity processing in XML parsers',
                    'references': ['https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing']
                })
        except Exception:
            pass

    def check_security_headers(self) -> None:
        """Check for security headers"""
        try:
            response = self.session.head(self.target_url, timeout=10)
            headers = response.headers

            security_headers = {
                'X-Frame-Options': 'Protects against clickjacking',
                'X-XSS-Protection': 'Enables XSS filtering',
                'X-Content-Type-Options': 'Prevents MIME type sniffing',
                'Strict-Transport-Security': 'Enforces HTTPS',
                'Content-Security-Policy': 'Prevents XSS and injection attacks',
                'Referrer-Policy': 'Controls referrer information',
                'Permissions-Policy': 'Controls browser features'
            }

            header_status = []
            for header, description in security_headers.items():
                present = header in headers
                header_status.append({
                    'header': header,
                    'present': present,
                    'value': headers.get(header, 'Not set'),
                    'description': description,
                    'status': 'Present' if present else 'Missing'
                })

            self.results['security_headers'] = header_status

        except Exception as e:
            print(f"Security headers check failed: {e}")

    def scan_ssl_tls(self) -> None:
        """Analyze SSL/TLS configuration"""
        if not self.parsed_url.scheme == 'https':
            return

        try:
            hostname = self.parsed_url.hostname
            port = self.parsed_url.port or 443

            # Get SSL certificate info
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    self.results['ssl_info'] = {
                        'version': version,
                        'cipher': cipher,
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'serial_number': cert['serialNumber']
                    }

                    # Check for weak configurations
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        self.results['vulnerabilities'].append({
                            'type': 'Weak SSL/TLS Version',
                            'severity': 'Medium',
                            'location': f"{hostname}:{port}",
                            'description': f'Weak SSL/TLS version detected: {version}',
                            'payload': f'SSL/TLS version: {version}',
                            'prevention': 'Upgrade to TLS 1.2 or higher',
                            'references': ['https://owasp.org/www-community/vulnerabilities/SSL_Version_2_and_3_are_still_supported']
                        })

        except Exception as e:
            print(f"SSL/TLS scan failed: {e}")

    def scan_dns_vulnerabilities(self) -> None:
        """Scan for DNS vulnerabilities"""
        hostname = self.parsed_url.hostname
        if not hostname:
            return

        try:
            # DNS zone transfer test
            try:
                answers = dns.resolver.resolve(hostname, 'AXFR')
                if answers:
                    self.results['vulnerabilities'].append({
                        'type': 'DNS Zone Transfer',
                        'severity': 'Medium',
                        'location': hostname,
                        'description': 'DNS zone transfer is allowed',
                        'payload': 'AXFR query successful',
                        'prevention': 'Restrict DNS zone transfers to authorized servers',
                        'references': ['https://owasp.org/www-community/vulnerabilities/Zone_transfer']
                    })
            except:
                pass

            # Subdomain enumeration
            subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging']
            found_subdomains = []

            for sub in subdomains:
                try:
                    full_domain = f"{sub}.{hostname}"
                    answers = dns.resolver.resolve(full_domain, 'A')
                    if answers:
                        found_subdomains.append(full_domain)
                except:
                    continue

            self.results['dns_info'] = {
                'hostname': hostname,
                'subdomains_found': found_subdomains
            }

        except Exception as e:
            print(f"DNS scan failed: {e}")

    def detect_cms_and_technologies(self) -> None:
        """Detect CMS and technologies"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            content = response.text.lower()
            headers = response.headers

            # CMS Detection
            cms_patterns = {
                'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json'],
                'Drupal': ['/sites/default/', '/modules/', 'drupal'],
                'Joomla': ['/administrator/', '/components/', 'joomla'],
                'Magento': ['/skin/frontend/', '/js/varien/', 'magento'],
                'PrestaShop': ['/modules/', '/themes/', 'prestashop']
            }

            detected_cms = []
            for cms, patterns in cms_patterns.items():
                for pattern in patterns:
                    if pattern in content:
                        detected_cms.append(cms)
                        break

            # Technology Detection
            technologies = []

            # Server headers
            server = headers.get('Server', '')
            if 'apache' in server.lower():
                technologies.append('Apache')
            elif 'nginx' in server.lower():
                technologies.append('Nginx')
            elif 'iis' in server.lower():
                technologies.append('IIS')

            # Programming languages
            if 'php' in server.lower() or '.php' in content:
                technologies.append('PHP')
            if 'asp.net' in server.lower() or 'aspnet' in content:
                technologies.append('ASP.NET')
            if 'django' in content or 'python' in server.lower():
                technologies.append('Python/Django')

            self.results['cms_info'] = {'detected': detected_cms}
            self.results['technologies'] = technologies

        except Exception as e:
            print(f"CMS/Technology detection failed: {e}")

    def get_results(self) -> Dict[str, Any]:
        """Get scan results"""
        return self.results