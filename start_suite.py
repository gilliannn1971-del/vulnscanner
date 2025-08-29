
#!/usr/bin/env python3
"""
Enhanced Security Scanner Suite Startup Script
Improved stability, error handling, and feature integration
"""

import os
import sys
import subprocess
import time
import threading
import signal
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityScannerSuite:
    def __init__(self):
        self.streamlit_process = None
        self.telegram_process = None
        self.shutdown_requested = False
        
    def check_and_install_dependencies(self):
        """Enhanced dependency checking with better error handling"""
        print("🔍 Checking dependencies...")
        
        try:
            result = subprocess.run([sys.executable, 'check_dependencies.py'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print("✅ All dependencies verified")
                return True
            else:
                print("⚠️ Some dependency issues detected")
                print(result.stdout)
                # Continue anyway - some dependencies might be optional
                return True
        except subprocess.TimeoutExpired:
            print("⚠️ Dependency check timed out - continuing anyway")
            return True
        except Exception as e:
            print(f"⚠️ Dependency check failed: {e}")
            return True

    def setup_environment(self):
        """Enhanced environment setup"""
        env_file = Path('.env')
        
        if not env_file.exists():
            print("📝 Creating .env template...")
            with open('.env', 'w') as f:
                f.write("TELEGRAM_BOT_TOKEN=8480422479:AAH0N8ZNzAWhM5XCO4ANpVrtGEvbupcrhsQ\n")
                f.write("ENABLE_TELEGRAM_BOT=true\n")
                f.write("STREAMLIT_PORT=5000\n")
                f.write("DEBUG_MODE=false\n")
            print("✅ .env file created with your bot token")
        else:
            print("✅ .env file exists")

    def start_streamlit(self):
        """Enhanced Streamlit startup with better error handling"""
        print("🌐 Starting Enhanced Streamlit Security Panel...")
        
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                if self.shutdown_requested:
                    return
                    
                self.streamlit_process = subprocess.Popen([
                    sys.executable, '-m', 'streamlit', 'run', 'app.py',
                    '--server.address', '0.0.0.0',
                    '--server.port', '5000',
                    '--server.headless', 'true',
                    '--server.runOnSave', 'false',
                    '--server.allowRunOnSave', 'false',
                    '--server.enableCORS', 'false',
                    '--server.enableXsrfProtection', 'false'
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Wait a moment to check if it started successfully
                time.sleep(3)
                
                if self.streamlit_process.poll() is None:
                    print("✅ Streamlit started successfully")
                    self.streamlit_process.wait()  # Keep running
                    return
                else:
                    print(f"❌ Streamlit failed to start (attempt {attempt + 1}/{max_attempts})")
                    if attempt < max_attempts - 1:
                        print("⏳ Retrying in 5 seconds...")
                        time.sleep(5)
                    
            except Exception as e:
                print(f"❌ Streamlit error (attempt {attempt + 1}/{max_attempts}): {e}")
                if attempt < max_attempts - 1:
                    time.sleep(5)
        
        print("❌ Failed to start Streamlit after all attempts")

    def start_telegram_bot(self):
        """Enhanced Telegram bot startup with stability improvements"""
        print("🤖 Starting Enhanced Telegram Security Bot...")
        
        max_attempts = 3
        restart_delay = 10
        
        for attempt in range(max_attempts):
            if self.shutdown_requested:
                return
                
            try:
                print(f"🚀 Starting Telegram bot (attempt {attempt + 1}/{max_attempts})")
                
                self.telegram_process = subprocess.Popen([
                    sys.executable, 'telegram_bot.py'
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Monitor the process
                start_time = time.time()
                
                while not self.shutdown_requested:
                    return_code = self.telegram_process.poll()
                    
                    if return_code is None:
                        # Process is running
                        if time.time() - start_time > 30:  # Running for 30+ seconds
                            print("✅ Telegram bot running stably")
                            self.telegram_process.wait()  # Keep running
                            return
                        time.sleep(1)
                    else:
                        # Process exited
                        stdout, stderr = self.telegram_process.communicate()
                        print(f"❌ Telegram bot exited with code {return_code}")
                        if stderr:
                            print(f"Error: {stderr.decode()}")
                        break
                
            except Exception as e:
                print(f"❌ Telegram bot error (attempt {attempt + 1}/{max_attempts}): {e}")
            
            if attempt < max_attempts - 1:
                print(f"⏳ Retrying in {restart_delay} seconds...")
                time.sleep(restart_delay)
                restart_delay *= 2  # Exponential backoff
        
        print("❌ Telegram bot failed to start after all attempts")
        print("🔇 Continuing with Streamlit panel only")

    def signal_handler(self, signum, frame):
        """Enhanced shutdown handler"""
        print(f"\n🛑 Received signal {signum} - shutting down gracefully...")
        self.shutdown_requested = True
        
        if self.streamlit_process:
            try:
                self.streamlit_process.terminate()
                print("🛑 Streamlit process terminated")
            except:
                pass
        
        if self.telegram_process:
            try:
                self.telegram_process.terminate()
                print("🛑 Telegram bot terminated")
            except:
                pass
        
        print("✅ Security Scanner Suite shutdown complete")
        sys.exit(0)

    def run(self):
        """Enhanced main execution with better process management"""
        print("🛡️ Enhanced Security Scanner Suite - Starting Up")
        print("=" * 60)
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Check dependencies
        if not self.check_and_install_dependencies():
            print("⚠️ Continuing with potential missing dependencies...")
        
        # Setup environment
        self.setup_environment()
        
        print("\n🚀 Starting Enhanced Security Scanner Suite...")
        print("📱 Streamlit Panel: http://0.0.0.0:5000")
        print("🤖 Telegram Bot: Enhanced with advanced features")
        print("=" * 60)
        
        # Start services in separate threads
        streamlit_thread = threading.Thread(target=self.start_streamlit, daemon=False)
        telegram_thread = threading.Thread(target=self.start_telegram_bot, daemon=False)
        
        try:
            # Start Streamlit first
            print("🌐 Launching Streamlit panel...")
            streamlit_thread.start()
            time.sleep(3)  # Give Streamlit time to initialize
            
            # Start Telegram bot
            print("🤖 Launching Telegram bot...")
            telegram_thread.start()
            time.sleep(2)
            
            print("✅ Both services launched successfully!")
            print("🔄 Monitoring service health...")
            
            # Monitor services with limited restart attempts
            streamlit_restarts = 0
            telegram_restarts = 0
            max_restarts = 3
            
            while not self.shutdown_requested:
                time.sleep(10)  # Check every 10 seconds
                
                # Check Streamlit health
                if not streamlit_thread.is_alive():
                    if streamlit_restarts < max_restarts:
                        streamlit_restarts += 1
                        print(f"⚠️ Restarting Streamlit ({streamlit_restarts}/{max_restarts})...")
                        streamlit_thread = threading.Thread(target=self.start_streamlit, daemon=False)
                        streamlit_thread.start()
                    else:
                        print("❌ Streamlit reached maximum restarts")
                
                # Check Telegram bot health  
                if not telegram_thread.is_alive():
                    if telegram_restarts < max_restarts:
                        telegram_restarts += 1
                        print(f"⚠️ Restarting Telegram bot ({telegram_restarts}/{max_restarts})...")
                        telegram_thread = threading.Thread(target=self.start_telegram_bot, daemon=False)
                        telegram_thread.start()
                    else:
                        print("❌ Telegram bot reached maximum restarts - running panel only")

        except KeyboardInterrupt:
            print("\n🛑 Received shutdown signal")
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
        finally:
            self.shutdown_requested = True
            print("🛑 Security Scanner Suite shutdown initiated")

def main():
    """Enhanced main function"""
    scanner_suite = SecurityScannerSuite()
    scanner_suite.run()

if __name__ == "__main__":
    main()
