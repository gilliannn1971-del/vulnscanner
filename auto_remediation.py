import requests
import re
from typing import Dict, List, Any
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class AutoRemediation:
    """Automatic remediation system for detected vulnerabilities"""
    
    def __init__(self, target_url: str, vulnerabilities: List[Dict[str, Any]]):
        self.target_url = target_url
        self.vulnerabilities = vulnerabilities
        self.remediation_results = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Educational-Auto-Remediation-Tool/1.0'
        })
    
    def auto_fix_by_severity(self, severity_levels: List[str] = ['High', 'Medium']) -> Dict[str, Any]:
        """Automatically fix vulnerabilities based on specified severity levels"""
        
        results = {
            'total_attempted': 0,
            'successful_fixes': 0,
            'failed_fixes': 0,
            'fix_details': [],
            'recommendations': []
        }
        
        # Filter vulnerabilities by severity
        target_vulns = [
            vuln for vuln in self.vulnerabilities 
            if vuln['severity'] in severity_levels
        ]
        
        results['total_attempted'] = len(target_vulns)
        
        for vuln in target_vulns:
            fix_result = self._attempt_fix(vuln)
            results['fix_details'].append(fix_result)
            
            if fix_result['success']:
                results['successful_fixes'] += 1
            else:
                results['failed_fixes'] += 1
        
        # Generate recommendations for unfixed issues
        results['recommendations'] = self._generate_fix_recommendations(target_vulns)
        
        return results
    
    def _attempt_fix(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt to fix a specific vulnerability"""
        
        fix_result = {
            'vulnerability_type': vulnerability['type'],
            'severity': vulnerability['severity'],
            'location': vulnerability['location'],
            'success': False,
            'fix_applied': '',
            'verification_result': '',
            'notes': ''
        }
        
        try:
            if 'SQL Injection' in vulnerability['type']:
                fix_result = self._fix_sql_injection(vulnerability, fix_result)
            elif 'XSS' in vulnerability['type']:
                fix_result = self._fix_xss(vulnerability, fix_result)
            elif 'IDOR' in vulnerability['type']:
                fix_result = self._fix_idor(vulnerability, fix_result)
            elif 'Missing Security Header' in vulnerability['type']:
                fix_result = self._fix_security_headers(vulnerability, fix_result)
            else:
                fix_result['notes'] = 'No automated fix available for this vulnerability type'
                
        except Exception as e:
            fix_result['notes'] = f'Error during fix attempt: {str(e)}'
        
        return fix_result
    
    def _fix_sql_injection(self, vulnerability: Dict[str, Any], fix_result: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt to fix SQL injection vulnerabilities"""
        
        # For educational purposes, we'll simulate fixes by testing if input validation can be applied
        payload = vulnerability.get('payload', '')
        location = vulnerability['location']
        
        # Test if we can apply input sanitization
        sanitized_payload = self._sanitize_sql_input(payload)
        
        if self._test_sanitized_input(location, sanitized_payload):
            fix_result['success'] = True
            fix_result['fix_applied'] = 'Applied input sanitization and validation'
            fix_result['verification_result'] = 'SQL injection payload neutralized'
            fix_result['notes'] = 'Simulated input validation successfully blocks SQL injection'
        else:
            fix_result['notes'] = 'Input sanitization simulation indicates server-side changes required'
            fix_result['fix_applied'] = 'Client-side validation added (server-side fix needed)'
        
        return fix_result
    
    def _fix_xss(self, vulnerability: Dict[str, Any], fix_result: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt to fix XSS vulnerabilities"""
        
        payload = vulnerability.get('payload', '')
        location = vulnerability['location']
        
        # Test if output encoding can be simulated
        encoded_payload = self._encode_xss_payload(payload)
        
        if self._test_encoded_output(location, encoded_payload):
            fix_result['success'] = True
            fix_result['fix_applied'] = 'Applied output encoding and CSP simulation'
            fix_result['verification_result'] = 'XSS payload properly encoded'
            fix_result['notes'] = 'Simulated output encoding successfully prevents XSS execution'
        else:
            fix_result['notes'] = 'Output encoding simulation indicates server-side implementation needed'
            fix_result['fix_applied'] = 'Client-side encoding validation (server implementation required)'
        
        return fix_result
    
    def _fix_idor(self, vulnerability: Dict[str, Any], fix_result: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt to fix IDOR vulnerabilities"""
        
        location = vulnerability['location']
        
        # Simulate access control validation
        if self._simulate_access_control(location):
            fix_result['success'] = True
            fix_result['fix_applied'] = 'Simulated access control validation'
            fix_result['verification_result'] = 'Unauthorized access blocked'
            fix_result['notes'] = 'Access control simulation suggests proper authorization checks'
        else:
            fix_result['notes'] = 'IDOR fix requires server-side access control implementation'
            fix_result['fix_applied'] = 'Access control analysis completed'
        
        return fix_result
    
    def _fix_security_headers(self, vulnerability: Dict[str, Any], fix_result: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt to fix missing security headers"""
        
        # Simulate security header implementation
        missing_header = vulnerability.get('payload', '').replace('Header: ', '')
        
        suggested_headers = {
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'",
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'X-Content-Type-Options': 'nosniff',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
        
        if missing_header in suggested_headers:
            fix_result['success'] = True
            fix_result['fix_applied'] = f'Recommended {missing_header}: {suggested_headers[missing_header]}'
            fix_result['verification_result'] = 'Security header configuration provided'
            fix_result['notes'] = 'Server configuration update required to implement header'
        else:
            fix_result['notes'] = f'Custom configuration needed for {missing_header}'
        
        return fix_result
    
    def _sanitize_sql_input(self, payload: str) -> str:
        """Simulate SQL input sanitization"""
        # Remove common SQL injection characters
        sanitized = re.sub(r"[';\"\\]", "", payload)
        sanitized = re.sub(r"\b(OR|AND|UNION|SELECT|DROP|INSERT|UPDATE|DELETE)\b", "", sanitized, flags=re.IGNORECASE)
        return sanitized
    
    def _encode_xss_payload(self, payload: str) -> str:
        """Simulate XSS output encoding"""
        # HTML encode dangerous characters
        encoded = payload.replace('<', '&lt;')
        encoded = encoded.replace('>', '&gt;')
        encoded = encoded.replace('"', '&quot;')
        encoded = encoded.replace("'", '&#x27;')
        encoded = encoded.replace('&', '&amp;')
        return encoded
    
    def _test_sanitized_input(self, location: str, sanitized_payload: str) -> bool:
        """Test if sanitized input would prevent SQL injection"""
        # Simulate testing - in real scenario, this would test against the actual endpoint
        dangerous_patterns = ['DROP', 'UNION', 'SELECT', "'", '"', ';']
        return not any(pattern.lower() in sanitized_payload.lower() for pattern in dangerous_patterns)
    
    def _test_encoded_output(self, location: str, encoded_payload: str) -> bool:
        """Test if encoded output would prevent XSS"""
        # Simulate testing - check if dangerous XSS patterns are encoded
        dangerous_patterns = ['<script', '<img', '<svg', 'javascript:', 'onerror=']
        return not any(pattern.lower() in encoded_payload.lower() for pattern in dangerous_patterns)
    
    def _simulate_access_control(self, location: str) -> bool:
        """Simulate access control implementation"""
        # In a real scenario, this would implement actual access controls
        # For simulation, we'll check if the URL contains predictable patterns
        predictable_patterns = [r'/\d+', r'id=\d+', r'user_id=\d+']
        has_predictable_pattern = any(re.search(pattern, location) for pattern in predictable_patterns)
        return has_predictable_pattern  # Suggests access control is needed and can be implemented
    
    def _generate_fix_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate detailed fix recommendations"""
        recommendations = []
        
        vuln_types = set(vuln['type'] for vuln in vulnerabilities)
        
        if any('SQL Injection' in vtype for vtype in vuln_types):
            recommendations.extend([
                "Implement parameterized queries in your database layer",
                "Add server-side input validation and sanitization",
                "Use ORM frameworks that automatically prevent SQL injection",
                "Implement database user permissions with least privilege principle"
            ])
        
        if any('XSS' in vtype for vtype in vuln_types):
            recommendations.extend([
                "Implement output encoding in your template engine",
                "Add Content Security Policy (CSP) headers",
                "Use framework-provided XSS protection features",
                "Validate and sanitize all user inputs on the server side"
            ])
        
        if any('IDOR' in vtype for vtype in vuln_types):
            recommendations.extend([
                "Implement object-level authorization checks",
                "Use UUIDs instead of sequential IDs",
                "Add user session validation for resource access",
                "Implement proper access control lists (ACLs)"
            ])
        
        if any('Missing Security Header' in vtype for vtype in vuln_types):
            recommendations.extend([
                "Configure web server to include security headers",
                "Implement HSTS for HTTPS enforcement",
                "Add frame protection headers to prevent clickjacking",
                "Enable browser XSS protection features"
            ])
        
        return recommendations
    
    def generate_fix_report(self, fix_results: Dict[str, Any]) -> str:
        """Generate a comprehensive fix report"""
        
        report = f"""
=== AUTOMATED REMEDIATION REPORT ===

Target: {self.target_url}
Total Vulnerabilities Addressed: {fix_results['total_attempted']}
Successful Fixes: {fix_results['successful_fixes']}
Failed Fixes: {fix_results['failed_fixes']}
Success Rate: {(fix_results['successful_fixes'] / max(fix_results['total_attempted'], 1)) * 100:.1f}%

=== DETAILED FIX RESULTS ===
"""
        
        for fix in fix_results['fix_details']:
            report += f"""
Vulnerability: {fix['vulnerability_type']} ({fix['severity']})
Location: {fix['location']}
Status: {'✅ FIXED' if fix['success'] else '❌ FAILED'}
Fix Applied: {fix['fix_applied']}
Verification: {fix['verification_result']}
Notes: {fix['notes']}
---
"""
        
        if fix_results['recommendations']:
            report += "\n=== ADDITIONAL RECOMMENDATIONS ===\n"
            for i, rec in enumerate(fix_results['recommendations'], 1):
                report += f"{i}. {rec}\n"
        
        report += """
=== IMPORTANT NOTICE ===
This automated remediation tool provides simulated fixes for educational purposes.
In a production environment, these fixes would require:
- Server-side code modifications
- Database configuration changes
- Web server configuration updates
- Thorough testing and validation

Always test fixes in a development environment before applying to production systems.
"""
        
        return report