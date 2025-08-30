
#!/usr/bin/env python3

import asyncio
from api_fuzzing_engine import APIFuzzingEngine
from attack_chaining_engine import AttackChainingEngine
from integrated_attack_system import IntegratedAttackSystem

def test_api_fuzzing():
    """Test API fuzzing engine"""
    print("🔍 Testing API Fuzzing Engine...")
    
    # Test with a target URL
    target_url = "https://httpbin.org"
    api_fuzzer = APIFuzzingEngine(target_url)
    
    # Discover endpoints
    print("Discovering API endpoints...")
    endpoints = api_fuzzer.discover_api_endpoints()
    print(f"Found {len(endpoints)} endpoints:")
    for endpoint in endpoints[:5]:  # Show first 5
        print(f"  • {endpoint}")
    
    # Fuzz endpoints
    print("\nFuzzing discovered endpoints...")
    results = api_fuzzer.fuzz_discovered_endpoints(aggressive=False)
    
    print(f"Fuzzing Results:")
    print(f"  • Total endpoints tested: {results['total_endpoints']}")
    print(f"  • Vulnerabilities found: {results['vulnerabilities_found']}")
    print(f"  • Authentication bypasses: {results['authentication_bypasses']}")
    print(f"  • Injection vulnerabilities: {results['injection_vulnerabilities']}")
    
    return results

def test_attack_chaining():
    """Test attack chaining engine"""
    print("\n⛓️ Testing Attack Chaining Engine...")
    
    # Mock vulnerabilities for testing
    mock_vulnerabilities = [
        {
            'type': 'SQL Injection',
            'location': 'https://example.com/search?q=test',
            'severity': 'High'
        },
        {
            'type': 'Cross-Site Scripting (XSS)',
            'location': 'https://example.com/comment',
            'severity': 'Medium'
        },
        {
            'type': 'IDOR',
            'location': 'https://example.com/user/123',
            'severity': 'High'
        }
    ]
    
    target_url = "https://example.com"
    chain_engine = AttackChainingEngine(target_url, mock_vulnerabilities)
    
    # Analyze available chains
    print("Analyzing vulnerability chains...")
    analysis = chain_engine.analyze_vulnerability_chains()
    
    print(f"Chain Analysis Results:")
    print(f"  • Available chains: {len(analysis['available_chains'])}")
    print(f"  • Recommended chains: {len(analysis['recommended_chains'])}")
    
    for chain in analysis['available_chains']:
        print(f"  • {chain['name']} ({chain['severity']}) - {chain['steps']} steps")
    
    return analysis

def test_integrated_system():
    """Test integrated attack system"""
    print("\n🚀 Testing Integrated Attack System...")
    
    # Mock vulnerabilities
    mock_vulnerabilities = [
        {
            'type': 'SQL Injection',
            'location': 'https://httpbin.org/get?id=1',
            'severity': 'Critical'
        }
    ]
    
    target_url = "https://httpbin.org"
    integrated_system = IntegratedAttackSystem(target_url, mock_vulnerabilities)
    
    print("Integrated system initialized successfully!")
    print(f"  • Target URL: {target_url}")
    print(f"  • Vulnerabilities loaded: {len(mock_vulnerabilities)}")
    print(f"  • API Fuzzer ready: {integrated_system.api_fuzzer is not None}")
    print(f"  • Chain Engine ready: {integrated_system.chain_engine is not None}")
    
    return True

async def run_full_test():
    """Run comprehensive test of all new engines"""
    print("═══════════════════════════════════════")
    print("    TESTING NEW ATTACK ENGINES")
    print("═══════════════════════════════════════")
    
    try:
        # Test individual engines
        api_results = test_api_fuzzing()
        chain_results = test_attack_chaining()
        integration_test = test_integrated_system()
        
        print("\n✅ All tests completed successfully!")
        print(f"API Fuzzing: Found {api_results['vulnerabilities_found']} vulnerabilities")
        print(f"Attack Chaining: {len(chain_results['available_chains'])} chains available")
        print(f"Integration: {'✅ Success' if integration_test else '❌ Failed'}")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Run the test
    asyncio.run(run_full_test())
