import json
import datetime
from typing import Dict, Any

class ReportGenerator:
    """Generate various report formats for vulnerability scan results"""
    
    def __init__(self, scan_results: Dict[str, Any]):
        self.scan_results = scan_results
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def generate_json_report(self) -> str:
        """Generate JSON format report"""
        report = {
            "scan_metadata": {
                "target_url": self.scan_results.get('target_url', 'Unknown'),
                "scan_timestamp": self.timestamp,
                "report_generated": self.timestamp,
                "scanner_version": "Educational Vulnerability Scanner v1.0"
            },
            "executive_summary": {
                "total_vulnerabilities": self.scan_results.get('total_vulnerabilities', 0),
                "high_severity": self.scan_results.get('high_severity', 0),
                "medium_severity": self.scan_results.get('medium_severity', 0),
                "low_severity": self.scan_results.get('low_severity', 0),
                "risk_score": self._calculate_risk_score()
            },
            "detailed_findings": self.scan_results.get('vulnerabilities', []),
            "security_headers": self.scan_results.get('security_headers', []),
            "recommendations": self._generate_recommendations()
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def generate_html_report(self) -> str:
        """Generate HTML format report"""
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        security_headers = self.scan_results.get('security_headers', [])
        
        # Sort vulnerabilities by severity
        severity_order = {'High': 0, 'Medium': 1, 'Low': 2}
        vulnerabilities.sort(key=lambda x: severity_order.get(x['severity'], 3))
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #333;
            margin: 0;
            font-size: 2.5em;
        }}
        .metadata {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background-color: #fff;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            font-size: 2em;
        }}
        .high {{ color: #dc3545; }}
        .medium {{ color: #fd7e14; }}
        .low {{ color: #28a745; }}
        .vulnerability {{
            border: 1px solid #dee2e6;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .vulnerability-header {{
            padding: 15px;
            font-weight: bold;
            font-size: 1.1em;
        }}
        .vulnerability-header.high {{
            background-color: #f8d7da;
            color: #721c24;
            border-bottom: 2px solid #dc3545;
        }}
        .vulnerability-header.medium {{
            background-color: #fff3cd;
            color: #856404;
            border-bottom: 2px solid #fd7e14;
        }}
        .vulnerability-header.low {{
            background-color: #d4edda;
            color: #155724;
            border-bottom: 2px solid #28a745;
        }}
        .vulnerability-body {{
            padding: 20px;
        }}
        .vulnerability-body h4 {{
            margin-top: 0;
            color: #495057;
        }}
        .code-block {{
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 10px;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            overflow-x: auto;
        }}
        .prevention {{
            background-color: #e7f3ff;
            border-left: 4px solid #007bff;
            padding: 15px;
            margin: 15px 0;
        }}
        .headers-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .headers-table th,
        .headers-table td {{
            border: 1px solid #dee2e6;
            padding: 12px;
            text-align: left;
        }}
        .headers-table th {{
            background-color: #f8f9fa;
            font-weight: bold;
        }}
        .disclaimer {{
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 5px;
            padding: 15px;
            margin-top: 30px;
        }}
        .no-vulnerabilities {{
            text-align: center;
            padding: 40px;
            background-color: #d4edda;
            color: #155724;
            border-radius: 8px;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Vulnerability Scan Report</h1>
            <p><strong>Educational Security Assessment</strong></p>
        </div>
        
        <div class="metadata">
            <h2>Scan Information</h2>
            <p><strong>Target URL:</strong> {self.scan_results.get('target_url', 'Unknown')}</p>
            <p><strong>Scan Date:</strong> {self.timestamp}</p>
            <p><strong>Scanner:</strong> Educational Vulnerability Scanner v1.0</p>
            <p><strong>Risk Score:</strong> {self._calculate_risk_score()}/100</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3 class="high">{self.scan_results.get('high_severity', 0)}</h3>
                <p>High Severity</p>
            </div>
            <div class="summary-card">
                <h3 class="medium">{self.scan_results.get('medium_severity', 0)}</h3>
                <p>Medium Severity</p>
            </div>
            <div class="summary-card">
                <h3 class="low">{self.scan_results.get('low_severity', 0)}</h3>
                <p>Low Severity</p>
            </div>
            <div class="summary-card">
                <h3>{self.scan_results.get('total_vulnerabilities', 0)}</h3>
                <p>Total Issues</p>
            </div>
        </div>
        
        <h2>Detailed Findings</h2>
        """
        
        if vulnerabilities:
            for vuln in vulnerabilities:
                severity_class = vuln['severity'].lower()
                html_content += f"""
        <div class="vulnerability">
            <div class="vulnerability-header {severity_class}">
                {vuln['type']} - {vuln['severity']} Severity
            </div>
            <div class="vulnerability-body">
                <h4>Location:</h4>
                <p>{vuln['location']}</p>
                
                <h4>Description:</h4>
                <p>{vuln['description']}</p>
                """
                
                if vuln.get('payload'):
                    html_content += f"""
                <h4>Payload Used:</h4>
                <div class="code-block">{vuln['payload']}</div>
                """
                
                html_content += f"""
                <div class="prevention">
                    <h4>Prevention:</h4>
                    <pre>{vuln['prevention']}</pre>
                </div>
                """
                
                if vuln.get('references'):
                    html_content += """
                <h4>References:</h4>
                <ul>
                """
                    for ref in vuln['references']:
                        html_content += f"<li>{ref}</li>"
                    html_content += "</ul>"
                
                html_content += """
            </div>
        </div>
                """
        else:
            html_content += """
        <div class="no-vulnerabilities">
            <h3>🎉 No vulnerabilities detected!</h3>
            <p>The target appears to be secure against the tested attack vectors.</p>
        </div>
            """
        
        # Security headers section
        if security_headers:
            html_content += """
        <h2>Security Headers Analysis</h2>
        <table class="headers-table">
            <thead>
                <tr>
                    <th>Header</th>
                    <th>Status</th>
                    <th>Value</th>
                    <th>Importance</th>
                </tr>
            </thead>
            <tbody>
            """
            
            for header in security_headers:
                status_class = 'high' if header['Status'] == 'Missing' and header['Importance'] == 'High' else ''
                html_content += f"""
                <tr class="{status_class}">
                    <td>{header['Header']}</td>
                    <td>{header['Status']}</td>
                    <td>{header['Value']}</td>
                    <td>{header['Importance']}</td>
                </tr>
                """
            
            html_content += """
            </tbody>
        </table>
            """
        
        # Recommendations
        recommendations = self._generate_recommendations()
        if recommendations:
            html_content += """
        <h2>Recommendations</h2>
        <ul>
            """
            for rec in recommendations:
                html_content += f"<li>{rec}</li>"
            html_content += """
        </ul>
            """
        
        # Disclaimer
        html_content += """
        <div class="disclaimer">
            <h3>⚠️ Educational Disclaimer</h3>
            <p>This report is generated by an educational vulnerability scanner. It is intended for learning purposes and authorized security testing only. Always ensure you have proper permission before scanning any website or application. The developers are not responsible for any misuse of this tool.</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html_content
    
    def _calculate_risk_score(self) -> int:
        """Calculate a risk score based on vulnerabilities found"""
        high_count = self.scan_results.get('high_severity', 0)
        medium_count = self.scan_results.get('medium_severity', 0)
        low_count = self.scan_results.get('low_severity', 0)
        
        # Weight the severity levels
        score = (high_count * 30) + (medium_count * 15) + (low_count * 5)
        
        # Cap at 100
        return min(score, 100)
    
    def _generate_recommendations(self) -> list:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        vuln_types = set(vuln['type'] for vuln in vulnerabilities)
        
        if any('SQL Injection' in vtype for vtype in vuln_types):
            recommendations.append("Implement parameterized queries and input validation to prevent SQL injection attacks")
        
        if any('XSS' in vtype for vtype in vuln_types):
            recommendations.append("Implement proper output encoding and Content Security Policy (CSP) to prevent XSS attacks")
        
        if any('IDOR' in vtype for vtype in vuln_types):
            recommendations.append("Implement proper access controls and object-level authorization checks")
        
        if any('Missing Security Header' in vtype for vtype in vuln_types):
            recommendations.append("Configure security headers to enhance browser-based protection mechanisms")
        
        # General recommendations
        if vulnerabilities:
            recommendations.extend([
                "Conduct regular security assessments and penetration testing",
                "Implement a Web Application Firewall (WAF) for additional protection",
                "Keep all software components updated with latest security patches",
                "Train development team on secure coding practices"
            ])
        else:
            recommendations.extend([
                "Continue maintaining good security practices",
                "Regular security assessments to ensure continued protection",
                "Stay updated with latest security threats and mitigation strategies"
            ])
        
        return recommendations
import json
import datetime
from typing import Dict, Any

class ReportGenerator:
    """Generate various report formats for vulnerability scan results"""
    
    def __init__(self, scan_results: Dict[str, Any]):
        self.scan_results = scan_results
        
    def generate_json_report(self) -> str:
        """Generate JSON format report"""
        report = {
            'scan_info': {
                'target_url': self.scan_results.get('target_url'),
                'scan_timestamp': self.scan_results.get('scan_timestamp'),
                'total_vulnerabilities': self.scan_results.get('total_vulnerabilities', 0)
            },
            'vulnerability_summary': {
                'critical': self.scan_results.get('critical_severity', 0),
                'high': self.scan_results.get('high_severity', 0),
                'medium': self.scan_results.get('medium_severity', 0),
                'low': self.scan_results.get('low_severity', 0),
                'info': self.scan_results.get('info_severity', 0)
            },
            'vulnerabilities': self.scan_results.get('vulnerabilities', []),
            'security_headers': self.scan_results.get('security_headers', []),
            'infrastructure': {
                'target_ip': self.scan_results.get('target_ip'),
                'open_ports': self.scan_results.get('open_ports', []),
                'services': self.scan_results.get('services', {})
            }
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def generate_html_report(self) -> str:
        """Generate HTML format report"""
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        target_url = self.scan_results.get('target_url', 'Unknown')
        timestamp = datetime.datetime.fromtimestamp(
            self.scan_results.get('scan_timestamp', 0)
        ).strftime('%Y-%m-%d %H:%M:%S')
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .vulnerability {{ margin: 10px 0; padding: 15px; border-left: 4px solid #ccc; }}
        .critical {{ border-left-color: #8b0000; background-color: #ffe6e6; }}
        .high {{ border-left-color: #ff0000; background-color: #ffe6e6; }}
        .medium {{ border-left-color: #ffa500; background-color: #fff4e6; }}
        .low {{ border-left-color: #008000; background-color: #e6ffe6; }}
        .info {{ border-left-color: #0000ff; background-color: #e6f3ff; }}
        .payload {{ background-color: #f5f5f5; padding: 10px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Vulnerability Scan Report</h1>
        <p><strong>Target:</strong> {target_url}</p>
        <p><strong>Scan Date:</strong> {timestamp}</p>
        <p><strong>Total Vulnerabilities:</strong> {len(vulnerabilities)}</p>
    </div>
    
    <h2>Vulnerabilities Found</h2>
"""
        
        if not vulnerabilities:
            html += "<p>No vulnerabilities detected.</p>"
        else:
            for vuln in vulnerabilities:
                severity_class = vuln['severity'].lower()
                html += f"""
    <div class="vulnerability {severity_class}">
        <h3>{vuln['type']} - {vuln['severity']} Severity</h3>
        <p><strong>Location:</strong> {vuln['location']}</p>
        <p><strong>Description:</strong> {vuln['description']}</p>
        <div class="payload"><strong>Payload:</strong> {vuln.get('payload', 'N/A')}</div>
        <p><strong>Prevention:</strong> {vuln['prevention']}</p>
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html
