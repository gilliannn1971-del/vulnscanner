
#!/usr/bin/env python3
"""
Health Check Script for Security Scanner Suite
Verifies that both Streamlit app and Telegram bot are running
"""

import requests
import subprocess
import sys
import time

def check_streamlit():
    """Check if Streamlit app is running"""
    try:
        response = requests.get("http://0.0.0.0:5000/_stcore/health", timeout=5)
        if response.status_code == 200:
            print("✅ Streamlit app is healthy")
            return True
    except:
        pass
    
    print("❌ Streamlit app is not responding")
    return False

def check_telegram_bot():
    """Check if Telegram bot process is running"""
    try:
        result = subprocess.run(['pgrep', '-f', 'telegram_bot.py'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Telegram bot process is running")
            return True
    except:
        pass
    
    print("❌ Telegram bot process not found")
    return False

def main():
    """Main health check function"""
    print("🔍 Security Scanner Suite - Health Check")
    print("=" * 40)
    
    streamlit_ok = check_streamlit()
    telegram_ok = check_telegram_bot()
    
    if streamlit_ok and telegram_ok:
        print("\n🎉 All services are healthy!")
        sys.exit(0)
    else:
        print(f"\n⚠️  Some services need attention")
        if not streamlit_ok:
            print("   - Restart Streamlit app")
        if not telegram_ok:
            print("   - Check Telegram bot token and restart")
        sys.exit(1)

if __name__ == "__main__":
    main()
