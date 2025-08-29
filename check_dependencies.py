
#!/usr/bin/env python3
"""
Dependency checker for Security Scanner Suite
Verifies all required modules are installed and importable
"""

import sys
import importlib
import subprocess

# Required modules for the project
REQUIRED_MODULES = [
    'streamlit',
    'requests',
    'beautifulsoup4',
    'pandas',
    'dnspython',
    'python-dotenv',
    'aiohttp',
    'mysql.connector',
    'paramiko',
    'psycopg2',
    'jwt',
    'pymongo',
    'pymysql',
    'pyodbc',
    'whois',
    'redis',
    'trafilatura',
    'telegram'
]

# Module name mappings for imports
MODULE_MAPPINGS = {
    'beautifulsoup4': 'bs4',
    'dnspython': 'dns',
    'python-dotenv': 'dotenv',
    'mysql-connector-python': 'mysql.connector',
    'psycopg2-binary': 'psycopg2',
    'pyjwt': 'jwt',
    'python-whois': 'whois',
    'python-telegram-bot': 'telegram'
}

def check_module(module_name):
    """Check if a module can be imported"""
    import_name = MODULE_MAPPINGS.get(module_name, module_name)
    
    try:
        importlib.import_module(import_name)
        return True, None
    except ImportError as e:
        return False, str(e)

def install_missing_modules(missing_modules):
    """Install missing modules using pip"""
    if not missing_modules:
        return True
    
    print(f"Installing missing modules: {', '.join(missing_modules)}")
    
    try:
        subprocess.run([
            sys.executable, '-m', 'pip', 'install'
        ] + missing_modules, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to install modules: {e}")
        return False

def main():
    """Main dependency checking function"""
    print("🔍 Checking Security Scanner Suite Dependencies...")
    print("=" * 50)
    
    missing_modules = []
    failed_imports = []
    
    for module in REQUIRED_MODULES:
        success, error = check_module(module)
        
        if success:
            print(f"✅ {module}")
        else:
            print(f"❌ {module} - {error}")
            missing_modules.append(module)
            failed_imports.append((module, error))
    
    print("=" * 50)
    
    if missing_modules:
        print(f"\n❌ Missing {len(missing_modules)} modules")
        print("Attempting to install missing dependencies...")
        
        if install_missing_modules(missing_modules):
            print("✅ All dependencies installed successfully!")
            
            # Re-check after installation
            print("\n🔍 Re-checking dependencies...")
            still_missing = []
            
            for module in missing_modules:
                success, error = check_module(module)
                if not success:
                    still_missing.append(module)
                    print(f"❌ {module} still missing after installation")
                else:
                    print(f"✅ {module} now available")
            
            if still_missing:
                print(f"\n❌ {len(still_missing)} modules still missing:")
                for module in still_missing:
                    print(f"  - {module}")
                return False
            else:
                print("\n✅ All dependencies are now available!")
                return True
        else:
            print("❌ Failed to install some dependencies")
            return False
    else:
        print("✅ All dependencies are installed and available!")
        return True

if __name__ == "__main__":
    success = main()
    if not success:
        print("\n⚠️ Some dependencies are missing. Please install them manually:")
        print("Run: pip install streamlit python-telegram-bot requests beautifulsoup4 pandas")
        sys.exit(1)
    else:
        print("\n🚀 Ready to start Security Scanner Suite!")
