import requests
import json
import time
import re
import threading
import queue
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse, urlencode
from typing import Dict, List, Any, Optional, Tuple
import itertools
import random
import string
from datetime import datetime
import concurrent.futures

class APIFuzzingEngine:
    """Advanced API fuzzing engine for REST/GraphQL endpoints"""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'API-Fuzzer/1.0 (Educational Security Testing)',
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json'
        })

        self.discovered_endpoints = []
        self.vulnerabilities = []
        self.api_documentation = {}
        self.authentication_tokens = []
        self.rate_limit_info = {}

    def discover_api_endpoints(self) -> List[str]:
        """Discover API endpoints automatically with advanced techniques"""
        endpoints = []

        try:
            # Check common API paths
            api_paths = [
                '/api', '/api/v1', '/api/v2', '/api/v3', '/rest', '/graphql',
                '/swagger', '/openapi', '/docs', '/api-docs', '/swagger-ui',
                '/redoc', '/api/swagger', '/api/docs', '/v1', '/v2',
                '/admin/api', '/internal/api', '/private/api', '/dev/api',
                '/test/api', '/staging/api', '/beta/api', '/alpha/api'
            ]

            # Add framework-specific paths
            framework_paths = {
                'laravel': ['/api/user', '/api/auth'],
                'django': ['/api/admin/', '/api/auth/'],
                'rails': ['/api/v1/users', '/api/sessions'],
                'express': ['/api/users', '/api/auth', '/api/login'],
                'flask': ['/api/user', '/api/token']
            }

            for framework, paths in framework_paths.items():
                api_paths.extend(paths)

            for path in api_paths:
                test_url = f"{self.base_url}{path}"
                try:
                    response = self.session.get(test_url, timeout=5)
                    if response.status_code in [200, 201, 401, 403, 405]:
                        endpoints.append(test_url)

                        # Try to discover more endpoints from response
                        discovered = self._extract_endpoints_from_response(response.text)
                        endpoints.extend(discovered)

                except:
                    continue

            # JavaScript file analysis for API endpoints
            js_endpoints = self._discover_endpoints_from_js()
            endpoints.extend(js_endpoints)

            # Sitemap and robots.txt analysis
            sitemap_endpoints = self._discover_from_sitemap()
            endpoints.extend(sitemap_endpoints)

        except Exception as e:
            print(f"API discovery error: {e}")

        return list(set(endpoints))  # Remove duplicates

    def _discover_from_robots_txt(self, endpoints: set):
        """Discover endpoints from robots.txt"""
        try:
            response = self.session.get(f"{self.base_url}/robots.txt", timeout=10)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if line.strip().startswith(('Disallow:', 'Allow:')):
                        path = line.split(':', 1)[1].strip()
                        if '/api' in path.lower():
                            endpoints.add(f"{self.base_url}{path}")
        except Exception:
            pass

    def _discover_from_sitemap(self) -> List[str]:
        """Discover endpoints from sitemap.xml and robots.txt"""
        endpoints = []

        try:
            # Check sitemap.xml
            sitemap_url = f"{self.base_url}/sitemap.xml"
            response = self.session.get(sitemap_url, timeout=5)

            if response.status_code == 200:
                import re
                # Extract URLs from sitemap
                urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                for url in urls:
                    if '/api' in url or '/v1' in url or '/v2' in url:
                        endpoints.append(url)

            # Check robots.txt
            robots_url = f"{self.base_url}/robots.txt"
            response = self.session.get(robots_url, timeout=5)

            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    if 'Disallow:' in line or 'Allow:' in line:
                        path = line.split(':', 1)[1].strip()
                        if '/api' in path:
                            endpoints.append(f"{self.base_url}{path}")

        except Exception as e:
            print(f"Sitemap/robots discovery error: {e}")

        return endpoints


    def _extract_endpoints_from_response(self, response_text: str) -> List[str]:
        """Extract API endpoints from response content"""
        endpoints = []

        # Look for API endpoint patterns in JSON responses
        import re

        # Common API endpoint patterns
        patterns = [
            r'"/api/[^"]*"',
            r"'/api/[^']*'",
            r'/v\d+/[a-zA-Z0-9/_-]+',
            r'endpoint["\']:\s*["\'][^"\']*["\']',
            r'url["\']:\s*["\'][^"\']*api[^"\']*["\']'
        ]

        for pattern in patterns:
            matches = re.findall(pattern, response_text)
            for match in matches:
                endpoint = match.strip('"\'')
                if endpoint.startswith('/'):
                    endpoints.append(f"{self.base_url}{endpoint}")
                elif endpoint.startswith('http'):
                    endpoints.append(endpoint)

        return endpoints

    def _discover_endpoints_from_js(self) -> List[str]:
        """Discover API endpoints from JavaScript files"""
        endpoints = []

        try:
            # First get the main page to find JS files
            response = self.session.get(self.base_url, timeout=10)

            import re
            from bs4 import BeautifulSoup

            if BeautifulSoup:
                soup = BeautifulSoup(response.text, 'html.parser')

                # Find all script tags with src
                script_tags = soup.find_all('script', src=True)

                for script in script_tags:
                    js_url = script['src']
                    if js_url.startswith('/'):
                        js_url = f"{self.base_url}{js_url}"
                    elif not js_url.startswith('http'):
                        js_url = f"{self.base_url}/{js_url}"

                    try:
                        js_response = self.session.get(js_url, timeout=5)
                        js_endpoints = self._extract_endpoints_from_response(js_response.text)
                        endpoints.extend(js_endpoints)
                    except:
                        continue

        except Exception as e:
            print(f"JS endpoint discovery error: {e}")

        return endpoints

    def _discover_from_sitemap(self, endpoints: set):
        """Discover endpoints from sitemap.xml"""
        try:
            response = self.session.get(f"{self.base_url}/sitemap.xml", timeout=10)
            if response.status_code == 200:
                # Extract URLs from sitemap
                urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                for url in urls:
                    if '/api' in url.lower():
                        endpoints.add(url)
        except Exception:
            pass

    def _discover_graphql_endpoints(self, endpoints: set):
        """Discover GraphQL endpoints"""
        graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql', '/query']

        for path in graphql_paths:
            test_url = f"{self.base_url}{path}"

            # Test with introspection query
            introspection_query = {
                "query": """
                    query IntrospectionQuery {
                        __schema {
                            queryType { name }
                            mutationType { name }
                            subscriptionType { name }
                        }
                    }
                """
            }

            try:
                response = self.session.post(test_url, json=introspection_query, timeout=10)
                if response.status_code == 200 and 'data' in response.text:
                    endpoints.add(test_url)
                    # Store GraphQL schema info
                    self.api_documentation[test_url] = {
                        'type': 'GraphQL',
                        'introspection_response': response.json()
                    }
            except Exception:
                continue

    def _discover_swagger_endpoints(self, endpoints: set):
        """Discover Swagger/OpenAPI documentation"""
        swagger_paths = [
            '/swagger.json', '/swagger.yaml', '/openapi.json',
            '/api-docs', '/swagger-ui', '/docs/swagger',
            '/api/swagger.json', '/v1/swagger.json'
        ]

        for path in swagger_paths:
            test_url = f"{self.base_url}{path}"
            try:
                response = self.session.get(test_url, timeout=10)
                if response.status_code == 200:
                    try:
                        swagger_doc = response.json()
                        if 'swagger' in swagger_doc or 'openapi' in swagger_doc:
                            endpoints.add(test_url)
                            self._parse_swagger_doc(swagger_doc, endpoints)
                    except json.JSONDecodeError:
                        pass
            except Exception:
                continue

    def _parse_swagger_doc(self, swagger_doc: Dict, endpoints: set):
        """Parse Swagger documentation to extract endpoints"""
        if 'paths' in swagger_doc:
            base_path = swagger_doc.get('basePath', '')
            host = swagger_doc.get('host', '')

            for path, methods in swagger_doc['paths'].items():
                full_path = f"{base_path}{path}"
                endpoint_url = f"{self.base_url}{full_path}"
                endpoints.add(endpoint_url)

                # Store endpoint documentation
                self.api_documentation[endpoint_url] = {
                    'type': 'REST',
                    'methods': list(methods.keys()),
                    'swagger_info': methods
                }

    def fuzz_discovered_endpoints(self, aggressive: bool = False) -> Dict[str, Any]:
        """Fuzz all discovered endpoints"""
        results = {
            'total_endpoints': len(self.discovered_endpoints),
            'vulnerabilities_found': 0,
            'authentication_bypasses': 0,
            'injection_vulnerabilities': 0,
            'information_disclosures': 0,
            'rate_limit_bypasses': 0,
            'detailed_results': []
        }

        # Use threading for faster fuzzing
        max_workers = 10 if aggressive else 5

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []

            for endpoint in self.discovered_endpoints:
                future = executor.submit(self._fuzz_single_endpoint, endpoint, aggressive)
                futures.append(future)

            for future in concurrent.futures.as_completed(futures):
                try:
                    endpoint_results = future.result()
                    results['detailed_results'].append(endpoint_results)

                    # Update counters
                    for vuln in endpoint_results.get('vulnerabilities', []):
                        results['vulnerabilities_found'] += 1
                        if 'authentication' in vuln['type'].lower():
                            results['authentication_bypasses'] += 1
                        elif 'injection' in vuln['type'].lower():
                            results['injection_vulnerabilities'] += 1
                        elif 'disclosure' in vuln['type'].lower():
                            results['information_disclosures'] += 1
                        elif 'rate limit' in vuln['type'].lower():
                            results['rate_limit_bypasses'] += 1

                except Exception as e:
                    continue

        return results

    def _fuzz_single_endpoint(self, endpoint: str, aggressive: bool) -> Dict[str, Any]:
        """Fuzz a single API endpoint"""
        results = {
            'endpoint': endpoint,
            'methods_tested': [],
            'vulnerabilities': [],
            'response_times': [],
            'status_codes': {},
            'authentication_tests': [],
            'injection_tests': []
        }

        # Test different HTTP methods
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        if not aggressive:
            methods = ['GET', 'POST', 'PUT', 'DELETE']

        for method in methods:
            method_results = self._test_method_on_endpoint(endpoint, method, aggressive)
            results['methods_tested'].append(method)
            results['vulnerabilities'].extend(method_results.get('vulnerabilities', []))
            results['response_times'].extend(method_results.get('response_times', []))

            # Update status codes
            for status, count in method_results.get('status_codes', {}).items():
                results['status_codes'][status] = results['status_codes'].get(status, 0) + count

        # Test authentication bypasses
        auth_results = self._test_authentication_bypasses(endpoint)
        results['authentication_tests'] = auth_results
        results['vulnerabilities'].extend(auth_results.get('vulnerabilities', []))

        # Test injection vulnerabilities
        injection_results = self._test_injection_vulnerabilities(endpoint, aggressive)
        results['injection_tests'] = injection_results
        results['vulnerabilities'].extend(injection_results.get('vulnerabilities', []))

        return results

    def _test_method_on_endpoint(self, endpoint: str, method: str, aggressive: bool) -> Dict[str, Any]:
        """Test a specific HTTP method on an endpoint"""
        results = {
            'method': method,
            'vulnerabilities': [],
            'response_times': [],
            'status_codes': {},
            'interesting_responses': []
        }

        # Basic method test
        try:
            start_time = time.time()
            response = self.session.request(method, endpoint, timeout=15)
            response_time = time.time() - start_time

            results['response_times'].append(response_time)
            status = str(response.status_code)
            results['status_codes'][status] = results['status_codes'].get(status, 0) + 1

            # Check for interesting responses
            if response.status_code in [200, 201, 202]:
                results['interesting_responses'].append({
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'content_type': response.headers.get('Content-Type', ''),
                    'has_json': self._is_json_response(response)
                })

                # Check for sensitive data exposure
                if self._check_sensitive_data_exposure(response.text):
                    results['vulnerabilities'].append({
                        'type': 'Information Disclosure',
                        'severity': 'Medium',
                        'method': method,
                        'endpoint': endpoint,
                        'description': 'Sensitive information exposed in API response',
                        'evidence': 'Response contains sensitive data patterns'
                    })

            # Check for verbose error messages
            if response.status_code >= 400:
                if self._check_verbose_errors(response.text):
                    results['vulnerabilities'].append({
                        'type': 'Information Disclosure',
                        'severity': 'Low',
                        'method': method,
                        'endpoint': endpoint,
                        'description': 'Verbose error messages expose system information',
                        'evidence': f'HTTP {response.status_code} with detailed error'
                    })

        except Exception as e:
            pass

        # Test parameter fuzzing if aggressive
        if aggressive and method in ['GET', 'POST']:
            param_results = self._fuzz_parameters(endpoint, method)
            results['vulnerabilities'].extend(param_results.get('vulnerabilities', []))

        return results

    def _test_authentication_bypasses(self, endpoint: str) -> Dict[str, Any]:
        """Test various authentication bypass techniques"""
        results = {
            'vulnerabilities': [],
            'bypass_attempts': []
        }

        # Test without authentication
        try:
            response = self.session.get(endpoint, timeout=10)
            if response.status_code == 200:
                results['bypass_attempts'].append({
                    'method': 'No authentication',
                    'status_code': response.status_code,
                    'success': True
                })

                results['vulnerabilities'].append({
                    'type': 'Authentication Bypass',
                    'severity': 'High',
                    'endpoint': endpoint,
                    'description': 'API endpoint accessible without authentication',
                    'evidence': f'HTTP 200 response without credentials'
                })
        except Exception:
            pass

        # Test with invalid tokens
        invalid_tokens = [
            'Bearer invalid',
            'Bearer 123456',
            'Bearer null',
            'Bearer undefined',
            'Basic invalid',
            'Basic ' + 'YWRtaW46cGFzc3dvcmQ='  # admin:password
        ]

        for token in invalid_tokens:
            try:
                headers = {'Authorization': token}
                response = self.session.get(endpoint, headers=headers, timeout=10)

                if response.status_code == 200:
                    results['vulnerabilities'].append({
                        'type': 'Authentication Bypass',
                        'severity': 'High',
                        'endpoint': endpoint,
                        'description': f'API accepts invalid authentication token',
                        'evidence': f'Token: {token[:20]}...'
                    })

                results['bypass_attempts'].append({
                    'method': f'Invalid token: {token[:20]}...',
                    'status_code': response.status_code,
                    'success': response.status_code == 200
                })

            except Exception:
                continue

        # Test header manipulation
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Override-URL': '/admin'},
            {'X-HTTP-Method-Override': 'GET'}
        ]

        for headers in bypass_headers:
            try:
                response = self.session.get(endpoint, headers=headers, timeout=10)
                if response.status_code == 200:
                    results['vulnerabilities'].append({
                        'type': 'Authentication Bypass',
                        'severity': 'Medium',
                        'endpoint': endpoint,
                        'description': f'Header manipulation bypasses authentication',
                        'evidence': f'Headers: {headers}'
                    })
            except Exception:
                continue

        return results

    def _test_injection_vulnerabilities(self, endpoint: str, aggressive: bool) -> Dict[str, Any]:
        """Test for various injection vulnerabilities"""
        results = {
            'vulnerabilities': [],
            'injection_tests': []
        }

        # SQL Injection payloads
        sql_payloads = [
            "' OR 1=1--",
            "'; DROP TABLE users; --",
            "' UNION SELECT null,null,null--",
            "admin'--",
            "' OR 'a'='a"
        ]

        # NoSQL Injection payloads
        nosql_payloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$where": "function() { return true; }"}',
            '{"$regex": ".*"}',
            '{"$exists": true}'
        ]

        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>"
        ]

        # Command injection payloads
        cmd_payloads = [
            "; ls",
            "| whoami",
            "& dir",
            "; cat /etc/passwd",
            "&& ping 127.0.0.1"
        ]

        all_payloads = {
            'SQL Injection': sql_payloads,
            'NoSQL Injection': nosql_payloads if aggressive else [],
            'XSS': xss_payloads,
            'Command Injection': cmd_payloads if aggressive else []
        }

        for injection_type, payloads in all_payloads.items():
            for payload in payloads:
                # Test in URL parameters
                vuln_found = self._test_payload_in_parameters(endpoint, payload, injection_type)
                if vuln_found:
                    results['vulnerabilities'].append(vuln_found)

                # Test in POST body
                if aggressive:
                    vuln_found = self._test_payload_in_body(endpoint, payload, injection_type)
                    if vuln_found:
                        results['vulnerabilities'].append(vuln_found)

        return results

    def _test_payload_in_parameters(self, endpoint: str, payload: str, injection_type: str) -> Optional[Dict]:
        """Test injection payload in URL parameters"""
        # Add payload to common parameter names
        param_names = ['id', 'user', 'search', 'query', 'data', 'input', 'value']

        for param_name in param_names:
            test_url = f"{endpoint}?{param_name}={payload}"

            try:
                response = self.session.get(test_url, timeout=10)

                # Check for injection indicators
                if self._detect_injection_success(response.text, injection_type, payload):
                    return {
                        'type': injection_type,
                        'severity': 'High' if injection_type == 'SQL Injection' else 'Medium',
                        'endpoint': test_url,
                        'description': f'{injection_type} vulnerability in parameter {param_name}',
                        'evidence': f'Payload: {payload}'
                    }

            except Exception:
                continue

        return None

    def _test_payload_in_body(self, endpoint: str, payload: str, injection_type: str) -> Optional[Dict]:
        """Test injection payload in POST body"""
        # Test with JSON body
        json_bodies = [
            {'data': payload},
            {'input': payload},
            {'query': payload},
            {'search': payload}
        ]

        for body in json_bodies:
            try:
                response = self.session.post(endpoint, json=body, timeout=10)

                if self._detect_injection_success(response.text, injection_type, payload):
                    return {
                        'type': injection_type,
                        'severity': 'High',
                        'endpoint': endpoint,
                        'description': f'{injection_type} vulnerability in POST body',
                        'evidence': f'Payload: {payload}'
                    }

            except Exception:
                continue

        return None

    def _detect_injection_success(self, response_text: str, injection_type: str, payload: str) -> bool:
        """Detect if injection was successful"""
        response_lower = response_text.lower()

        if injection_type == 'SQL Injection':
            sql_errors = [
                'sql syntax', 'mysql_fetch', 'warning: mysql',
                'postgresql query failed', 'sqlite_', 'oracle error'
            ]
            return any(error in response_lower for error in sql_errors)

        elif injection_type == 'NoSQL Injection':
            nosql_errors = [
                'mongodb', 'bson', 'objectid', 'collection'
            ]
            return any(error in response_lower for error in nosql_errors)

        elif injection_type == 'XSS':
            return payload in response_text

        elif injection_type == 'Command Injection':
            cmd_indicators = [
                'uid=', 'gid=', 'total', 'drwx', 'volume serial number'
            ]
            return any(indicator in response_lower for indicator in cmd_indicators)

        return False

    def _fuzz_parameters(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Fuzz API parameters"""
        results = {'vulnerabilities': []}

        # Common parameter names to test
        param_names = [
            'id', 'user_id', 'admin', 'debug', 'test', 'dev',
            'limit', 'offset', 'page', 'size', 'count',
            'format', 'type', 'mode', 'action', 'cmd'
        ]

        # Parameter values that might cause issues
        dangerous_values = [
            '999999999',  # Large number
            '-1',         # Negative number
            '0',          # Zero
            '../../../etc/passwd',  # Path traversal
            '${7*7}',     # Expression injection
            '{{7*7}}',    # Template injection
            'true',       # Boolean
            'false',      # Boolean
            'null',       # Null
            'undefined'   # Undefined
        ]

        for param_name in param_names:
            for value in dangerous_values:
                try:
                    if method == 'GET':
                        test_url = f"{endpoint}?{param_name}={value}"
                        response = self.session.get(test_url, timeout=10)
                    else:
                        data = {param_name: value}
                        response = self.session.post(endpoint, json=data, timeout=10)

                    # Check for interesting responses
                    if response.status_code in [200, 500] and len(response.text) > 0:
                        if self._check_parameter_vulnerability(response.text, value):
                            results['vulnerabilities'].append({
                                'type': 'Parameter Vulnerability',
                                'severity': 'Medium',
                                'endpoint': endpoint,
                                'description': f'Parameter {param_name} accepts dangerous value',
                                'evidence': f'Value: {value}, Response length: {len(response.text)}'
                            })

                except Exception:
                    continue

        return results

    def _check_parameter_vulnerability(self, response_text: str, test_value: str) -> bool:
        """Check if parameter testing revealed vulnerability"""
        # Look for error messages, stack traces, or reflected values
        indicators = [
            'error', 'exception', 'stack trace', 'warning',
            'fatal', 'debug', 'traceback', test_value
        ]

        response_lower = response_text.lower()
        return any(indicator in response_lower for indicator in indicators)

    def _is_json_response(self, response) -> bool:
        """Check if response is JSON"""
        try:
            response.json()
            return True
        except:
            return False

    def _check_sensitive_data_exposure(self, response_text: str) -> bool:
        """Check for sensitive data in response"""
        sensitive_patterns = [
            r'password["\']?\s*:\s*["\'][^"\']+["\']',
            r'api[_-]?key["\']?\s*:\s*["\'][^"\']+["\']',
            r'secret["\']?\s*:\s*["\'][^"\']+["\']',
            r'token["\']?\s*:\s*["\'][^"\']+["\']',
            r'ssn["\']?\s*:\s*["\'][^"\']+["\']',
            r'credit[_-]?card["\']?\s*:\s*["\'][^"\']+["\']',
            r'\b\d{16}\b',  # Credit card numbers
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN format
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'  # Email addresses
        ]

        for pattern in sensitive_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False

    def _check_verbose_errors(self, response_text: str) -> bool:
        """Check for verbose error messages"""
        error_indicators = [
            'stack trace', 'traceback', 'exception in thread',
            'caused by:', 'at java.', 'at com.', 'at org.',
            'file not found', 'access denied', 'permission denied',
            'internal server error', 'database error', 'sql error'
        ]

        response_lower = response_text.lower()
        return any(indicator in response_lower for indicator in error_indicators)

    def generate_api_report(self, results: Dict[str, Any]) -> str:
        """Generate comprehensive API fuzzing report"""
        report = f"""
═══════════════════════════════════════
          API FUZZING REPORT
═══════════════════════════════════════

🎯 TARGET: {self.base_url}
📊 ENDPOINTS DISCOVERED: {results['total_endpoints']}
🔍 VULNERABILITIES FOUND: {results['vulnerabilities_found']}

📈 VULNERABILITY BREAKDOWN:
├─ Authentication Bypasses: {results['authentication_bypasses']}
├─ Injection Vulnerabilities: {results['injection_vulnerabilities']}
├─ Information Disclosures: {results['information_disclosures']}
└─ Rate Limit Bypasses: {results['rate_limit_bypasses']}

🔍 DISCOVERED ENDPOINTS:
"""

        for i, endpoint in enumerate(self.discovered_endpoints[:10], 1):
            report += f"{i:2d}. {endpoint}\n"

        if len(self.discovered_endpoints) > 10:
            report += f"    ... and {len(self.discovered_endpoints) - 10} more endpoints\n"

        # Add top vulnerabilities
        if results['vulnerabilities_found'] > 0:
            report += "\n🚨 CRITICAL VULNERABILITIES:\n"
            vuln_count = 0

            for endpoint_result in results['detailed_results']:
                for vuln in endpoint_result.get('vulnerabilities', []):
                    if vuln['severity'] in ['High', 'Critical'] and vuln_count < 5:
                        vuln_count += 1
                        report += f"{vuln_count:2d}. {vuln['type']} - {vuln['endpoint']}\n"
                        report += f"    Description: {vuln['description']}\n"
                        report += f"    Evidence: {vuln['evidence']}\n\n"

        report += "═══════════════════════════════════════\n"
        return report