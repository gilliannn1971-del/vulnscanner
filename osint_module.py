
import requests
import dns.resolver
import whois
import socket
import ssl
import subprocess
import re
from urllib.parse import urlparse
from typing import Dict, List, Any
import json
import time

class OSINTGatherer:
    """OSINT information gathering module"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.domain = urlparse(target_url).hostname
        self.results = {
            'domain_info': {},
            'subdomains': [],
            'social_media': [],
            'emails': [],
            'technologies': [],
            'certificates': {},
            'dns_records': {},
            'whois_info': {},
            'related_domains': [],
            'leaked_credentials': [],
            'public_files': [],
            'github_repos': []
        }
    
    def gather_all_intel(self) -> Dict[str, Any]:
        """Gather comprehensive OSINT information"""
        print(f"🔍 Gathering OSINT for {self.domain}...")
        
        try:
            self.get_whois_info()
            self.enumerate_subdomains()
            self.gather_dns_records()
            self.check_ssl_certificate()
            self.find_emails()
            self.detect_technologies()
            self.search_social_media()
            self.find_public_files()
            self.search_github()
            self.check_data_breaches()
        except Exception as e:
            print(f"OSINT gathering error: {e}")
        
        return self.results
    
    def get_whois_info(self) -> None:
        """Get WHOIS information"""
        try:
            domain_info = whois.whois(self.domain)
            self.results['whois_info'] = {
                'registrar': str(domain_info.registrar) if domain_info.registrar else 'Unknown',
                'creation_date': str(domain_info.creation_date) if domain_info.creation_date else 'Unknown',
                'expiration_date': str(domain_info.expiration_date) if domain_info.expiration_date else 'Unknown',
                'name_servers': domain_info.name_servers if domain_info.name_servers else [],
                'status': domain_info.status if domain_info.status else 'Unknown',
                'country': str(domain_info.country) if domain_info.country else 'Unknown'
            }
        except Exception as e:
            self.results['whois_info'] = {'error': str(e)}
    
    def enumerate_subdomains(self) -> None:
        """Enumerate subdomains"""
        common_subdomains = [
            'www', 'mail', 'email', 'webmail', 'ftp', 'admin', 'administrator',
            'test', 'testing', 'dev', 'development', 'staging', 'stage',
            'api', 'apis', 'cdn', 'assets', 'static', 'media', 'images',
            'blog', 'news', 'support', 'help', 'docs', 'documentation',
            'shop', 'store', 'payment', 'pay', 'secure', 'ssl',
            'login', 'auth', 'authentication', 'user', 'users', 'account',
            'mobile', 'm', 'wap', 'beta', 'alpha', 'demo', 'preview',
            'cpanel', 'whm', 'phpmyadmin', 'mysql', 'database', 'db',
            'ns1', 'ns2', 'dns1', 'dns2', 'mx', 'mx1', 'mx2',
            'server', 'servers', 'host', 'hosting', 'cloud', 'backup'
        ]
        
        found_subdomains = []
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{self.domain}"
                dns.resolver.resolve(full_domain, 'A')
                found_subdomains.append(full_domain)
                time.sleep(0.1)  # Rate limiting
            except:
                continue
        
        self.results['subdomains'] = found_subdomains
    
    def gather_dns_records(self) -> None:
        """Gather DNS records"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        dns_records = {}
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                dns_records[record_type] = [str(rdata) for rdata in answers]
            except:
                dns_records[record_type] = []
        
        self.results['dns_records'] = dns_records
    
    def check_ssl_certificate(self) -> None:
        """Check SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    self.results['certificates'] = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'alternative_names': cert.get('subjectAltName', [])
                    }
        except Exception as e:
            self.results['certificates'] = {'error': str(e)}
    
    def find_emails(self) -> None:
        """Find email addresses associated with domain"""
        try:
            # Search for emails in common sources
            search_queries = [
                f"site:{self.domain} email",
                f"site:{self.domain} contact",
                f"site:{self.domain} @{self.domain}"
            ]
            
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            found_emails = set()
            
            # Check main website
            try:
                response = requests.get(f"https://{self.domain}", timeout=10)
                emails = re.findall(email_pattern, response.text)
                found_emails.update(emails)
            except:
                pass
            
            # Check common email pages
            email_pages = ['/contact', '/about', '/team', '/staff', '/support']
            for page in email_pages:
                try:
                    response = requests.get(f"https://{self.domain}{page}", timeout=5)
                    emails = re.findall(email_pattern, response.text)
                    found_emails.update(emails)
                except:
                    continue
            
            self.results['emails'] = list(found_emails)
            
        except Exception as e:
            self.results['emails'] = []
    
    def detect_technologies(self) -> None:
        """Detect technologies used by the website"""
        try:
            response = requests.get(f"https://{self.domain}", timeout=10)
            headers = response.headers
            content = response.text.lower()
            
            technologies = []
            
            # Server detection
            server = headers.get('Server', '').lower()
            if 'apache' in server:
                technologies.append('Apache')
            elif 'nginx' in server:
                technologies.append('Nginx')
            elif 'iis' in server:
                technologies.append('IIS')
            
            # Framework detection
            if 'wordpress' in content or '/wp-content/' in content:
                technologies.append('WordPress')
            if 'drupal' in content or 'sites/default' in content:
                technologies.append('Drupal')
            if 'joomla' in content:
                technologies.append('Joomla')
            
            # Programming language detection
            if 'php' in server or '.php' in content:
                technologies.append('PHP')
            if 'asp.net' in headers.get('X-Powered-By', '').lower():
                technologies.append('ASP.NET')
            if 'django' in content or 'csrfmiddlewaretoken' in content:
                technologies.append('Django')
            
            # JavaScript frameworks
            if 'react' in content:
                technologies.append('React')
            if 'angular' in content:
                technologies.append('Angular')
            if 'vue' in content:
                technologies.append('Vue.js')
            
            self.results['technologies'] = technologies
            
        except Exception as e:
            self.results['technologies'] = []
    
    def search_social_media(self) -> None:
        """Search for social media profiles"""
        social_platforms = [
            'facebook.com',
            'twitter.com',
            'linkedin.com',
            'instagram.com',
            'youtube.com',
            'github.com',
            'reddit.com'
        ]
        
        found_profiles = []
        
        for platform in social_platforms:
            try:
                # Common username patterns
                usernames = [
                    self.domain.split('.')[0],
                    self.domain.replace('.', ''),
                    self.domain.replace('.com', '').replace('.org', '').replace('.net', '')
                ]
                
                for username in usernames:
                    profile_url = f"https://{platform}/{username}"
                    try:
                        response = requests.head(profile_url, timeout=5)
                        if response.status_code == 200:
                            found_profiles.append(profile_url)
                    except:
                        continue
                        
            except:
                continue
        
        self.results['social_media'] = found_profiles
    
    def find_public_files(self) -> None:
        """Find publicly accessible files"""
        common_files = [
            'robots.txt',
            'sitemap.xml',
            '.htaccess',
            'wp-config.php',
            'config.php',
            'database.sql',
            'backup.sql',
            '.env',
            'admin.php',
            'phpinfo.php',
            'test.php',
            'info.php'
        ]
        
        found_files = []
        
        for file in common_files:
            try:
                response = requests.head(f"https://{self.domain}/{file}", timeout=5)
                if response.status_code == 200:
                    found_files.append(f"https://{self.domain}/{file}")
            except:
                continue
        
        self.results['public_files'] = found_files
    
    def search_github(self) -> None:
        """Search for GitHub repositories"""
        try:
            search_terms = [
                self.domain,
                self.domain.split('.')[0],
                f'"{self.domain}"'
            ]
            
            found_repos = []
            
            for term in search_terms:
                try:
                    # Note: This would require GitHub API in production
                    # For now, we'll simulate with basic search
                    github_url = f"https://github.com/search?q={term}"
                    found_repos.append(f"Search: {github_url}")
                except:
                    continue
            
            self.results['github_repos'] = found_repos
            
        except Exception as e:
            self.results['github_repos'] = []
    
    def check_data_breaches(self) -> None:
        """Check for known data breaches (simulated)"""
        try:
            # In a real implementation, this would check against breach databases
            # For educational purposes, we'll simulate some common scenarios
            
            breach_indicators = []
            
            # Check if domain appears in common breach patterns
            if any(term in self.domain for term in ['mail', 'email', 'user']):
                breach_indicators.append("Domain pattern suggests potential for email-related breaches")
            
            if len(self.results['emails']) > 0:
                breach_indicators.append(f"Found {len(self.results['emails'])} email addresses - check against breach databases")
            
            self.results['leaked_credentials'] = breach_indicators
            
        except Exception as e:
            self.results['leaked_credentials'] = []

def perform_osint_scan(target_url: str) -> Dict[str, Any]:
    """Perform comprehensive OSINT scan"""
    gatherer = OSINTGatherer(target_url)
    return gatherer.gather_all_intel()
import requests
import socket
import ssl
import dns.resolver
import whois
import re
from urllib.parse import urlparse
from typing import Dict, List, Any

def perform_osint_scan(target_url: str) -> Dict[str, Any]:
    """Perform OSINT reconnaissance on target"""
    
    results = {
        'target_url': target_url,
        'whois_info': {},
        'subdomains': [],
        'emails': [],
        'technologies': [],
        'social_media': [],
        'public_files': [],
        'dns_records': {},
        'ssl_info': {}
    }
    
    try:
        # Parse domain from URL
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc or parsed_url.path
        
        # Remove www if present
        if domain.startswith('www.'):
            domain = domain[4:]
            
        # WHOIS Information
        try:
            whois_info = whois.whois(domain)
            results['whois_info'] = {
                'registrar': getattr(whois_info, 'registrar', 'Unknown'),
                'creation_date': str(getattr(whois_info, 'creation_date', 'Unknown')),
                'expiration_date': str(getattr(whois_info, 'expiration_date', 'Unknown')),
                'country': getattr(whois_info, 'country', 'Unknown'),
                'organization': getattr(whois_info, 'org', 'Unknown')
            }
        except Exception as e:
            results['whois_info'] = {'error': str(e)}
        
        # DNS Records
        try:
            for record_type in ['A', 'AAAA', 'MX', 'TXT', 'NS']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    results['dns_records'][record_type] = [str(answer) for answer in answers]
                except:
                    pass
        except Exception as e:
            results['dns_records'] = {'error': str(e)}
        
        # Subdomain enumeration (basic)
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'forum', 'support', 'help', 'docs', 'cdn'
        ]
        
        for sub in common_subdomains:
            try:
                subdomain = f"{sub}.{domain}"
                socket.gethostbyname(subdomain)
                results['subdomains'].append(subdomain)
            except:
                pass
        
        # Technology detection (basic)
        try:
            response = requests.get(target_url, timeout=10)
            headers = response.headers
            content = response.text.lower()
            
            # Detect technologies from headers
            if 'x-powered-by' in headers:
                results['technologies'].append(f"Powered by: {headers['x-powered-by']}")
            if 'server' in headers:
                results['technologies'].append(f"Server: {headers['server']}")
            
            # Detect technologies from content
            if 'wordpress' in content:
                results['technologies'].append('WordPress')
            if 'joomla' in content:
                results['technologies'].append('Joomla')
            if 'drupal' in content:
                results['technologies'].append('Drupal')
            if 'react' in content:
                results['technologies'].append('React')
            if 'angular' in content:
                results['technologies'].append('Angular')
            if 'jquery' in content:
                results['technologies'].append('jQuery')
                
        except Exception as e:
            results['technologies'] = [f'Error: {str(e)}']
        
        # Email extraction
        try:
            response = requests.get(target_url, timeout=10)
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, response.text)
            results['emails'] = list(set(emails))  # Remove duplicates
        except Exception as e:
            results['emails'] = []
        
        # Social media detection
        social_patterns = {
            'Facebook': r'facebook\.com/[a-zA-Z0-9._-]+',
            'Twitter': r'twitter\.com/[a-zA-Z0-9._-]+',
            'LinkedIn': r'linkedin\.com/[a-zA-Z0-9._/-]+',
            'Instagram': r'instagram\.com/[a-zA-Z0-9._-]+',
            'YouTube': r'youtube\.com/[a-zA-Z0-9._/-]+'
        }
        
        try:
            response = requests.get(target_url, timeout=10)
            for platform, pattern in social_patterns.items():
                matches = re.findall(pattern, response.text)
                for match in matches:
                    results['social_media'].append(f"{platform}: {match}")
        except:
            pass
        
        # Public files detection
        common_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', 'wp-config.php.bak',
            'config.php.bak', 'backup.sql', 'database.sql', '.git/config'
        ]
        
        for file in common_files:
            try:
                file_url = f"{target_url.rstrip('/')}/{file}"
                response = requests.head(file_url, timeout=5)
                if response.status_code == 200:
                    results['public_files'].append(file)
            except:
                pass
        
        # SSL Information
        try:
            hostname = domain
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    results['ssl_info'] = {
                        'version': ssock.version(),
                        'cipher': ssock.cipher()[0] if ssock.cipher() else 'Unknown',
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'serial_number': cert.get('serialNumber', 'Unknown'),
                        'not_after': cert.get('notAfter', 'Unknown')
                    }
        except Exception as e:
            results['ssl_info'] = {'error': str(e)}
    
    except Exception as e:
        results['error'] = str(e)
    
    return results
