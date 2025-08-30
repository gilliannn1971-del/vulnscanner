#!/usr/bin/env python3
"""
Unified startup script for Security Scanner Suite
Starts both Streamlit app and Telegram bot with proper error handling
"""

import os
import sys
import subprocess
import time
import threading
import signal
from pathlib import Path

def check_and_install_dependencies():
    """Check and install missing dependencies"""
    print("🔍 Checking dependencies...")

    try:
        result = subprocess.run([sys.executable, 'check_dependencies.py'], 
                              capture_output=True, text=True)

        if result.returncode == 0:
            print("✅ All dependencies verified")
            return True
        else:
            print("❌ Dependency issues detected")
            print(result.stdout)
            print(result.stderr)
            return False
    except Exception as e:
        print(f"⚠️ Could not run dependency check: {e}")
        return True  # Continue anyway

def setup_environment():
    """Setup environment and configuration"""
    env_file = Path('.env')

    if not env_file.exists():
        print("📝 Creating .env template...")
        with open('.env', 'w') as f:
            f.write("TELEGRAM_BOT_TOKEN=YOUR_BOT_TOKEN_HERE\n")
            f.write("# Add your Telegram bot token above\n")
        print("⚠️ Please update .env file with your Telegram bot token")
    else:
        print("✅ .env file exists")

def start_streamlit():
    """Start Streamlit application"""
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
    """Start the Telegram bot in a separate thread"""
    def run_bot():
        max_retries = 3
        retry_count = 0

        while retry_count < max_retries:
            try:
                subprocess.run([sys.executable, 'telegram_bot.py'])
                break  # If successful, exit loop
            except Exception as e:
                retry_count += 1
                print(f"❌ Telegram bot error (attempt {retry_count}/{max_retries}): {e}")
                if retry_count < max_retries:
                    print(f"⚠️ Retrying in 10 seconds...")
                    time.sleep(10)
                else:
                    print("🔇 Telegram bot disabled after multiple failures")
                    print("📋 Please check your bot token configuration")
                    break

    thread = threading.Thread(target=run_bot, daemon=True)
    thread.start()
    print("✅ Telegram bot thread started")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print("\n🛑 Shutting down Security Scanner Suite...")
    sys.exit(0)

def main():
    """Main startup function"""
    print("🔍 Security Scanner Suite - Unified Startup")
    print("=" * 50)

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Check dependencies
    if not check_and_install_dependencies():
        print("❌ Dependency check failed. Attempting to continue...")

    # Setup environment
    setup_environment()

    print("\n🚀 Starting Security Scanner Suite...")
    print("📱 Streamlit Panel: http://0.0.0.0:5000")
    print("🤖 Telegram Bot: Will start after panel initialization")
    print("=" * 50)

    # Create threads for parallel execution
    streamlit_thread = threading.Thread(target=start_streamlit, daemon=True)
    telegram_thread = threading.Thread(target=start_telegram_bot, daemon=True)

    try:
        # Start Streamlit first
        streamlit_thread.start()
        print("✅ Streamlit thread started")

        # Start Telegram bot after delay
        telegram_thread.start()
        print("✅ Telegram bot thread started")

        # Keep main thread alive
        print("🔄 Both services running. Press Ctrl+C to stop...")

        while True:
            time.sleep(1)

            # Check if threads are still alive
            if not streamlit_thread.is_alive():
                print("⚠️ Streamlit thread died, restarting...")
                streamlit_thread = threading.Thread(target=start_streamlit, daemon=True)
                streamlit_thread.start()

            if not telegram_thread.is_alive():
                print("⚠️ Telegram bot thread died, restarting...")
                telegram_thread = threading.Thread(target=start_telegram_bot, daemon=True)  
                telegram_thread.start()

    except KeyboardInterrupt:
        print("\n🛑 Received shutdown signal")
    except Exception as e:
        print(f"\n❌ Startup error: {e}")
    finally:
        print("🛑 Security Scanner Suite shutdown complete")

if __name__ == "__main__":
    main()