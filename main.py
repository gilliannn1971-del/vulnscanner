
#!/usr/bin/env python3
"""
Main startup script for Security Scanner Suite
Runs both Streamlit app and Telegram bot in parallel
"""

import os
import sys
import subprocess
import threading
import time
import signal
from pathlib import Path

def setup_environment():
    """Setup environment and configuration"""
    env_file = Path('.env')
    
    if not env_file.exists():
        print("📝 Creating .env template...")
        with open('.env', 'w') as f:
            f.write("TELEGRAM_BOT_TOKEN=YOUR_BOT_TOKEN_HERE\n")
            f.write("ENABLE_TELEGRAM_BOT=true\n")
        print("⚠️ Please update .env file with your Telegram bot token")
    else:
        print("✅ .env file exists")

def start_streamlit():
    """Start Streamlit application on port 5000"""
    print("🌐 Starting Streamlit Security Scanner Panel...")
    try:
        subprocess.run([
            sys.executable, '-m', 'streamlit', 'run', 'app.py',
            '--server.address', '0.0.0.0',
            '--server.port', '5000',
            '--server.headless', 'true',
            '--server.runOnSave', 'true'
        ])
    except KeyboardInterrupt:
        print("🛑 Streamlit app stopped")
    except Exception as e:
        print(f"❌ Streamlit app error: {e}")

def start_telegram_bot():
    """Start Telegram bot"""
    print("🤖 Starting Telegram bot...")
    try:
        # Small delay to let Streamlit start first
        time.sleep(3)
        subprocess.run([sys.executable, 'telegram_bot.py'])
    except KeyboardInterrupt:
        print("🛑 Telegram bot stopped")
    except Exception as e:
        print(f"❌ Telegram bot error: {e}")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print("\n🛑 Shutting down Security Scanner Suite...")
    sys.exit(0)

def main():
    """Main startup function"""
    print("🔍 Security Scanner Suite - Starting Services")
    print("=" * 50)
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Setup environment
    setup_environment()
    
    print("\n🚀 Starting Security Scanner Suite...")
    print("📱 Streamlit Panel: http://0.0.0.0:5000")
    print("🤖 Telegram Bot: Starting after panel...")
    print("=" * 50)
    
    # Create threads for parallel execution
    streamlit_thread = threading.Thread(target=start_streamlit, daemon=True)
    telegram_thread = threading.Thread(target=start_telegram_bot, daemon=True)
    
    try:
        # Start both services
        streamlit_thread.start()
        print("✅ Streamlit thread started")
        
        telegram_thread.start()
        print("✅ Telegram bot thread started")
        
        print("🔄 Both services running. Press Ctrl+C to stop...")
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n🛑 Received shutdown signal")
    except Exception as e:
        print(f"\n❌ Startup error: {e}")
    finally:
        print("🛑 Security Scanner Suite shutdown complete")

if __name__ == "__main__":
    main()
