
#!/usr/bin/env python3
"""
Security Scanner Suite Startup Script
Initializes and starts both the Streamlit app and Telegram bot
"""

import os
import sys
import subprocess
import time
import threading
from pathlib import Path

def check_dependencies():
    """Check if all required dependencies are available"""
    required_modules = [
        'streamlit', 'telegram', 'requests', 'beautifulsoup4', 
        'pandas', 'dnspython', 'python-dotenv'
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            __import__(module.replace('-', '_'))
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"❌ Missing modules: {', '.join(missing_modules)}")
        print("Installing missing dependencies...")
        subprocess.run([sys.executable, '-m', 'pip', 'install'] + missing_modules)
    else:
        print("✅ All dependencies are installed")

def setup_environment():
    """Setup environment variables and configuration"""
    env_file = Path('.env')
    
    if not env_file.exists():
        print("⚠️  .env file not found, creating template...")
        with open('.env', 'w') as f:
            f.write("TELEGRAM_BOT_TOKEN=YOUR_BOT_TOKEN_HERE\n")
        print("📝 Please update .env file with your Telegram bot token")
    
    # Load environment variables
    try:
        from dotenv import load_dotenv
        load_dotenv()
        
        bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
        if not bot_token or bot_token == 'YOUR_BOT_TOKEN_HERE':
            print("⚠️  Please set your TELEGRAM_BOT_TOKEN in the .env file")
        else:
            print("✅ Telegram bot token configured")
            
    except ImportError:
        print("⚠️  python-dotenv not available, skipping environment setup")

def start_streamlit():
    """Start the Streamlit application"""
    try:
        print("🚀 Starting Streamlit Security Scanner Panel...")
        subprocess.run([
            sys.executable, '-m', 'streamlit', 'run', 'app.py',
            '--server.address', '0.0.0.0',
            '--server.port', '5000',
            '--server.allowRunOnSave', 'true',
            '--server.headless', 'true'
        ])
    except Exception as e:
        print(f"❌ Failed to start Streamlit app: {e}")

def start_telegram_bot():
    """Start the Telegram bot"""
    try:
        print("🤖 Starting Telegram Security Scanner Bot...")
        subprocess.run([sys.executable, 'telegram_bot.py'])
    except Exception as e:
        print(f"❌ Failed to start Telegram bot: {e}")

def main():
    """Main startup function"""
    print("🔍 Security Scanner Suite - Starting Up...")
    print("=" * 50)
    
    # Check dependencies
    check_dependencies()
    
    # Setup environment
    setup_environment()
    
    print("\n🚀 Starting Security Scanner Suite...")
    print("📱 Streamlit Panel: http://0.0.0.0:5000")
    print("🤖 Telegram Bot: Check your bot on Telegram")
    print("=" * 50)
    
    # Create threads for parallel execution
    streamlit_thread = threading.Thread(target=start_streamlit, daemon=True)
    telegram_thread = threading.Thread(target=start_telegram_bot, daemon=True)
    
    # Start both services
    streamlit_thread.start()
    time.sleep(2)  # Give Streamlit a moment to start
    telegram_thread.start()
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down Security Scanner Suite...")
        sys.exit(0)

if __name__ == "__main__":
    main()
