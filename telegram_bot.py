
import os
import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import io
from dotenv import load_dotenv

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, Document
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes
from telegram.constants import ParseMode

from comprehensive_scanner import ComprehensiveScanner
from report_generator import ReportGenerator
from auto_remediation import AutoRemediation
try:
    from attack_engine import AttackEngine
except ImportError:
    AttackEngine = None
try:
    from vps_vds_attacks import VPSVDSAttacks
except ImportError:
    VPSVDSAttacks = None

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class VulnerabilityTelegramBot:
    def __init__(self):
        self.user_sessions = {}  # Store user scan sessions
        self.active_scans = {}   # Track active scans
        
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Start command handler"""
        user_id = update.effective_user.id
        
        welcome_text = """
🔍 **Educational Vulnerability Scanner Bot**

Welcome! This bot helps you understand web security vulnerabilities through educational scanning.

⚠️ **IMPORTANT**: Only scan websites you own or have explicit permission to test.

**Available Commands:**
/scan - Start a vulnerability scan
/config - Configure scan settings
/help - Show help information
/status - Check current scan status

**Features:**
✅ SQL Injection Detection
✅ XSS Vulnerability Scanning
✅ IDOR Testing
✅ Port Scanning
✅ SSL/TLS Analysis
✅ VPS/VDS Attack Testing
✅ Auto-Remediation
✅ Interactive Attack Engine

Get started with /scan to begin scanning a target!
        """
        
        await update.message.reply_text(welcome_text, parse_mode=ParseMode.MARKDOWN)
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Help command handler"""
        help_text = """
🔍 **Vulnerability Scanner Bot Help**

**Main Commands:**
• `/scan` - Start a new vulnerability scan
• `/config` - Configure scan parameters
• `/status` - Check active scan status
• `/stop` - Stop current scan
• `/help` - Show this help message

**Attack Analysis:**
• `/attacks` - View detailed attack information
• `/exploits` - Show successful exploits and data
• `/credentials` - Display discovered credentials

**Scan Types:**
• **Basic Scan** - SQL injection, XSS, IDOR
• **Aggressive Scan** - Advanced payloads and techniques
• **Port Scan** - Network service enumeration
• **VPS/VDS Attack** - Server-level attacks
• **Auto-Fix** - Automated vulnerability remediation

**Report Formats:**
• JSON - Machine-readable format
• HTML - Human-friendly report
• Text - Quick summary

**Educational Purpose:**
This tool is designed for learning about web security. Always ensure you have permission before scanning any target.
        """
        
        await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)
    
    async def scan_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Start scan command handler"""
        user_id = update.effective_user.id
        
        # Check if user has active scan
        if user_id in self.active_scans:
            await update.message.reply_text(
                "⚠️ You already have an active scan. Use /status to check progress or /stop to cancel."
            )
            return
        
        # Initialize user session
        self.user_sessions[user_id] = {
            'step': 'target',
            'config': {
                'aggressive': False,
                'include_ports': True,
                'include_ssl': True,
                'include_dns': True,
                'max_pages': 3,
                'auto_fix': False,
                'attack_mode': False,
                'vps_attack': False
            }
        }
        
        await update.message.reply_text(
            "🎯 **Starting Vulnerability Scan**\n\n"
            "Please enter the target URL you want to scan:\n"
            "Example: `http://testhtml5.vulnweb.com`\n\n"
            "⚠️ Only scan websites you own or have permission to test!",
            parse_mode=ParseMode.MARKDOWN
        )
    
    async def config_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Configuration command handler"""
        user_id = update.effective_user.id
        
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = {
                'step': 'config',
                'config': {
                    'aggressive': False,
                    'include_ports': True,
                    'include_ssl': True,
                    'include_dns': True,
                    'max_pages': 3,
                    'auto_fix': False,
                    'attack_mode': False,
                    'vps_attack': False
                }
            }
        
        config = self.user_sessions[user_id]['config']
        
        keyboard = [
            [
                InlineKeyboardButton(f"Aggressive Scan: {'✅' if config['aggressive'] else '❌'}", callback_data="toggle_aggressive"),
                InlineKeyboardButton(f"Port Scanning: {'✅' if config['include_ports'] else '❌'}", callback_data="toggle_ports")
            ],
            [
                InlineKeyboardButton(f"SSL/TLS Check: {'✅' if config['include_ssl'] else '❌'}", callback_data="toggle_ssl"),
                InlineKeyboardButton(f"DNS Analysis: {'✅' if config['include_dns'] else '❌'}", callback_data="toggle_dns")
            ],
            [
                InlineKeyboardButton(f"Auto-Fix: {'✅' if config['auto_fix'] else '❌'}", callback_data="toggle_autofix"),
                InlineKeyboardButton(f"Attack Mode: {'✅' if config['attack_mode'] else '❌'}", callback_data="toggle_attack")
            ],
            [
                InlineKeyboardButton(f"VPS/VDS Attack: {'✅' if config['vps_attack'] else '❌'}", callback_data="toggle_vps"),
                InlineKeyboardButton(f"Max Pages: {config['max_pages']}", callback_data="set_pages")
            ],
            [
                InlineKeyboardButton("✅ Save Configuration", callback_data="save_config")
            ]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        config_text = f"""
⚙️ **Scan Configuration**

Current Settings:
• Aggressive Scanning: {'Enabled' if config['aggressive'] else 'Disabled'}
• Port Scanning: {'Enabled' if config['include_ports'] else 'Disabled'}
• SSL/TLS Analysis: {'Enabled' if config['include_ssl'] else 'Disabled'}
• DNS Vulnerability Check: {'Enabled' if config['include_dns'] else 'Disabled'}
• Auto-Remediation: {'Enabled' if config['auto_fix'] else 'Disabled'}
• Interactive Attack Mode: {'Enabled' if config['attack_mode'] else 'Disabled'}
• VPS/VDS Attacks: {'Enabled' if config['vps_attack'] else 'Disabled'}
• Maximum Pages to Scan: {config['max_pages']}

Tap buttons below to toggle settings:
        """
        
        await update.message.reply_text(config_text, reply_markup=reply_markup, parse_mode=ParseMode.MARKDOWN)
    
    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle button callbacks"""
        query = update.callback_query
        user_id = query.from_user.id
        data = query.data
        
        await query.answer()
        
        if user_id not in self.user_sessions:
            await query.edit_message_text("❌ Session expired. Please start again with /config")
            return
        
        config = self.user_sessions[user_id]['config']
        
        if data == "toggle_aggressive":
            config['aggressive'] = not config['aggressive']
        elif data == "toggle_ports":
            config['include_ports'] = not config['include_ports']
        elif data == "toggle_ssl":
            config['include_ssl'] = not config['include_ssl']
        elif data == "toggle_dns":
            config['include_dns'] = not config['include_dns']
        elif data == "toggle_autofix":
            config['auto_fix'] = not config['auto_fix']
        elif data == "toggle_attack":
            config['attack_mode'] = not config['attack_mode']
        elif data == "toggle_vps":
            config['vps_attack'] = not config['vps_attack']
        elif data == "set_pages":
            # Cycle through page options
            config['max_pages'] = 1 if config['max_pages'] >= 10 else config['max_pages'] + 1
        elif data == "save_config":
            await query.edit_message_text("✅ Configuration saved! Use /scan to start scanning.")
            return
        
        # Update the configuration display
        keyboard = [
            [
                InlineKeyboardButton(f"Aggressive Scan: {'✅' if config['aggressive'] else '❌'}", callback_data="toggle_aggressive"),
                InlineKeyboardButton(f"Port Scanning: {'✅' if config['include_ports'] else '❌'}", callback_data="toggle_ports")
            ],
            [
                InlineKeyboardButton(f"SSL/TLS Check: {'✅' if config['include_ssl'] else '❌'}", callback_data="toggle_ssl"),
                InlineKeyboardButton(f"DNS Analysis: {'✅' if config['include_dns'] else '❌'}", callback_data="toggle_dns")
            ],
            [
                InlineKeyboardButton(f"Auto-Fix: {'✅' if config['auto_fix'] else '❌'}", callback_data="toggle_autofix"),
                InlineKeyboardButton(f"Attack Mode: {'✅' if config['attack_mode'] else '❌'}", callback_data="toggle_attack")
            ],
            [
                InlineKeyboardButton(f"VPS/VDS Attack: {'✅' if config['vps_attack'] else '❌'}", callback_data="toggle_vps"),
                InlineKeyboardButton(f"Max Pages: {config['max_pages']}", callback_data="set_pages")
            ],
            [
                InlineKeyboardButton("✅ Save Configuration", callback_data="save_config")
            ]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        config_text = f"""
⚙️ **Scan Configuration**

Current Settings:
• Aggressive Scanning: {'Enabled' if config['aggressive'] else 'Disabled'}
• Port Scanning: {'Enabled' if config['include_ports'] else 'Disabled'}
• SSL/TLS Analysis: {'Enabled' if config['include_ssl'] else 'Disabled'}
• DNS Vulnerability Check: {'Enabled' if config['include_dns'] else 'Disabled'}
• Auto-Remediation: {'Enabled' if config['auto_fix'] else 'Disabled'}
• Interactive Attack Mode: {'Enabled' if config['attack_mode'] else 'Disabled'}
• VPS/VDS Attacks: {'Enabled' if config['vps_attack'] else 'Disabled'}
• Maximum Pages to Scan: {config['max_pages']}

Tap buttons below to toggle settings:
        """
        
        await query.edit_message_text(config_text, reply_markup=reply_markup, parse_mode=ParseMode.MARKDOWN)
    
    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle text messages"""
        user_id = update.effective_user.id
        message_text = update.message.text
        
        if user_id not in self.user_sessions:
            await update.message.reply_text(
                "Please start with /scan command to begin a vulnerability scan."
            )
            return
        
        session = self.user_sessions[user_id]
        
        if session['step'] == 'target':
            # Validate URL
            target_url = message_text.strip()
            
            if not target_url.startswith(('http://', 'https://')):
                await update.message.reply_text(
                    "❌ Please provide a valid URL starting with http:// or https://"
                )
                return
            
            # Start the scan
            session['target_url'] = target_url
            self.active_scans[user_id] = True
            
            await self.start_vulnerability_scan(update, context, target_url, session['config'])
    
    async def start_vulnerability_scan(self, update: Update, context: ContextTypes.DEFAULT_TYPE, target_url: str, config: Dict):
        """Start the vulnerability scanning process"""
        user_id = update.effective_user.id
        
        # Initialize scan results storage
        if not hasattr(self, 'last_scan_results'):
            self.last_scan_results = {}
        
        progress_message = await update.message.reply_text(
            f"🔍 **Starting Vulnerability Scan**\n\n"
            f"Target: `{target_url}`\n"
            f"Status: Initializing scanner...\n"
            f"Progress: ░░░░░░░░░░ 0%",
            parse_mode=ParseMode.MARKDOWN
        )
        
        try:
            # Initialize scanner
            scanner = ComprehensiveScanner(target_url)
            
            # Progress tracking
            progress_steps = [
                ("Checking target accessibility...", 10),
                ("Scanning ports and services...", 20),
                ("Analyzing web vulnerabilities...", 40),
                ("Testing SQL injection...", 50),
                ("Testing XSS vulnerabilities...", 60),
                ("Testing IDOR vulnerabilities...", 70),
                ("Checking SSL/TLS security...", 80),
                ("Analyzing DNS configuration...", 90),
                ("Generating report...", 95),
                ("Scan completed!", 100)
            ]
            
            for step_name, progress in progress_steps:
                if user_id not in self.active_scans:
                    await progress_message.edit_text("❌ **Scan Cancelled**")
                    return
                
                # Update progress
                progress_bar = "█" * (progress // 10) + "░" * (10 - progress // 10)
                await progress_message.edit_text(
                    f"🔍 **Vulnerability Scan In Progress**\n\n"
                    f"Target: `{target_url}`\n"
                    f"Status: {step_name}\n"
                    f"Progress: {progress_bar} {progress}%",
                    parse_mode=ParseMode.MARKDOWN
                )
                
                # Execute scan steps
                if progress == 10:
                    if not scanner.check_target_accessibility():
                        await progress_message.edit_text(
                            f"❌ **Scan Failed**\n\n"
                            f"Target `{target_url}` is not accessible.\n"
                            f"Please check the URL and try again."
                        )
                        del self.active_scans[user_id]
                        return
                
                elif progress == 20 and config['include_ports']:
                    scanner.scan_ports()
                
                elif progress == 40:
                    scanner.scan_web_vulnerabilities(aggressive=config['aggressive'])
                    scanner.detect_cms_and_technologies()
                
                elif progress == 80 and config['include_ssl']:
                    scanner.scan_ssl_tls()
                
                elif progress == 90 and config['include_dns']:
                    scanner.scan_dns_vulnerabilities()
                
                await asyncio.sleep(0.5)  # Small delay for UI updates
            
            # Get scan results
            results = scanner.get_results()
            
            # Store results for attack details
            self.last_scan_results[user_id] = results
            
            # Generate summary
            summary = self.generate_scan_summary(results)
            
            await progress_message.edit_text(summary, parse_mode=ParseMode.MARKDOWN)
            
            # Auto-remediation if enabled
            if config['auto_fix'] and results['vulnerabilities']:
                await self.run_auto_remediation(update, context, results, config)
            
            # Interactive attacks if enabled
            if config['attack_mode'] and results['vulnerabilities'] and AttackEngine:
                await self.run_interactive_attacks(update, context, results, config)
            
            # VPS/VDS attacks if enabled
            if config['vps_attack'] and hasattr(scanner, 'run_vps_vds_attacks'):
                await self.run_vps_attacks(update, context, scanner, config)
            
            # Generate and send reports
            await self.send_reports(update, context, results)
            
        except Exception as e:
            await progress_message.edit_text(
                f"❌ **Scan Error**\n\n"
                f"An error occurred during scanning:\n"
                f"`{str(e)}`\n\n"
                f"Please try again with a different target.",
                parse_mode=ParseMode.MARKDOWN
            )
        finally:
            if user_id in self.active_scans:
                del self.active_scans[user_id]
            if user_id in self.user_sessions:
                del self.user_sessions[user_id]
    
    async def run_auto_remediation(self, update: Update, context: ContextTypes.DEFAULT_TYPE, results: Dict, config: Dict):
        """Run auto-remediation on found vulnerabilities"""
        remediation_message = await update.message.reply_text(
            "🔧 **Starting Auto-Remediation**\n\nAnalyzing vulnerabilities for automatic fixes..."
        )
        
        try:
            auto_remediation = AutoRemediation(results['target_url'], results['vulnerabilities'])
            severity_filter = ['Critical', 'High', 'Medium']
            fix_results = auto_remediation.auto_fix_by_severity(severity_filter)
            
            fix_summary = f"""
🔧 **Auto-Remediation Results**

✅ **Attempted:** {fix_results['total_attempted']}
✅ **Successful:** {fix_results['successful_fixes']}
❌ **Failed:** {fix_results['failed_fixes']}
📊 **Success Rate:** {(fix_results['successful_fixes'] / max(fix_results['total_attempted'], 1)) * 100:.1f}%

**Top Fixes Applied:**
"""
            
            for i, fix in enumerate(fix_results['fix_details'][:3], 1):
                status_icon = "✅" if fix['success'] else "❌"
                fix_summary += f"{i}. {status_icon} {fix['vulnerability_type']}\n"
            
            await remediation_message.edit_text(fix_summary)
            
        except Exception as e:
            await remediation_message.edit_text(f"❌ Auto-remediation failed: {str(e)}")
    
    async def run_interactive_attacks(self, update: Update, context: ContextTypes.DEFAULT_TYPE, results: Dict, config: Dict):
        """Run interactive attacks on vulnerabilities"""
        attack_message = await update.message.reply_text(
            "⚔️ **Starting Interactive Attacks**\n\nExecuting vulnerability exploits..."
        )
        
        try:
            if AttackEngine:
                attack_engine = AttackEngine(results['target_url'], results['vulnerabilities'])
                attack_results = attack_engine.start_interactive_attacks()
                
                # Store attack results for detailed view
                self.attack_engine_results = attack_results
                
                attack_summary = f"""
⚔️ **Attack Execution Results**

🎯 **Total Attacks:** {attack_results.get('total_attacks', 0)}
✅ **Successful:** {attack_results.get('successful_exploits', 0)}
❌ **Failed:** {attack_results.get('failed_exploits', 0)}
📊 **Success Rate:** {(attack_results.get('successful_exploits', 0) / max(attack_results.get('total_attacks', 1), 1)) * 100:.1f}%

**Data Extracted:** {len(attack_results.get('extracted_data', []))}
**Credentials Found:** {len(attack_results.get('credentials_found', []))}
**Shells Obtained:** {len(attack_results.get('shells_obtained', []))}
"""
                
                if attack_results.get('credentials_found'):
                    attack_summary += "\n🔑 **Credentials Discovered:**\n"
                    for cred in attack_results['credentials_found'][:3]:
                        attack_summary += f"• {cred.get('data', 'N/A')}\n"
                
                await attack_message.edit_text(attack_summary)
            else:
                await attack_message.edit_text("❌ Interactive attack engine not available")
            
        except Exception as e:
            await attack_message.edit_text(f"❌ Interactive attacks failed: {str(e)}")
    
    async def run_vps_attacks(self, update: Update, context: ContextTypes.DEFAULT_TYPE, scanner: ComprehensiveScanner, config: Dict):
        """Run VPS/VDS attacks"""
        vps_message = await update.message.reply_text(
            "🚀 **Starting VPS/VDS Attacks**\n\nExecuting server-level attacks..."
        )
        
        try:
            vps_results = scanner.run_vps_vds_attacks()
            
            if vps_results:
                # Store VPS results for detailed view
                self.vps_exploit_results = vps_results
                
                vps_summary = f"""
🚀 **VPS/VDS Attack Results**

🎯 **Total Attacks:** {vps_results.get('total_attacks', 0)}
✅ **Successful:** {vps_results.get('successful_attacks', 0)}
🔑 **Credentials Found:** {len(vps_results.get('credentials_found', []))}
🐚 **Shells Obtained:** {len(vps_results.get('shells_obtained', []))}
"""
                
                if vps_results.get('credentials_found'):
                    vps_summary += "\n🔑 **Credentials Discovered:**\n"
                    for cred in vps_results['credentials_found'][:3]:
                        vps_summary += f"• {cred.get('service', 'Unknown')}: {cred.get('username', '')}:{cred.get('password', '')}\n"
                
                await vps_message.edit_text(vps_summary)
            else:
                await vps_message.edit_text("ℹ️ No VPS/VDS vulnerabilities found or applicable.")
                
        except Exception as e:
            await vps_message.edit_text(f"❌ VPS/VDS attacks failed: {str(e)}")
    
    def generate_scan_summary(self, results: Dict) -> str:
        """Generate a summary of scan results"""
        total_vulns = len(results['vulnerabilities'])
        critical_count = len([v for v in results['vulnerabilities'] if v['severity'] == 'Critical'])
        high_count = len([v for v in results['vulnerabilities'] if v['severity'] == 'High'])
        medium_count = len([v for v in results['vulnerabilities'] if v['severity'] == 'Medium'])
        low_count = len([v for v in results['vulnerabilities'] if v['severity'] == 'Low'])
        
        summary = f"""
✅ **Vulnerability Scan Complete**

🎯 **Target:** `{results['target_url']}`
📊 **Total Issues Found:** {total_vulns}

**Severity Breakdown:**
🔴 Critical: {critical_count}
🟠 High: {high_count}
🟡 Medium: {medium_count}
🟢 Low: {low_count}

**Infrastructure:**
"""
        
        if results.get('target_ip'):
            summary += f"📍 **IP:** `{results['target_ip']}`\n"
        
        if results.get('open_ports'):
            summary += f"🔌 **Open Ports:** {', '.join(map(str, results['open_ports']))}\n"
        
        if results.get('services'):
            summary += "🛠️ **Services:**\n"
            for port, service in list(results['services'].items())[:3]:
                summary += f"  • Port {port}: {service}\n"
        
        if total_vulns > 0:
            summary += "\n**Top Vulnerabilities:**\n"
            for i, vuln in enumerate(results['vulnerabilities'][:5], 1):
                severity_emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(vuln['severity'], '⚪')
                summary += f"{i}. {severity_emoji} {vuln['type']}\n"
        else:
            summary += "\n🎉 **No vulnerabilities detected!**"
        
        return summary
    
    async def send_reports(self, update: Update, context: ContextTypes.DEFAULT_TYPE, results: Dict):
        """Send detailed reports to user"""
        try:
            report_gen = ReportGenerator(results)
            
            # Generate JSON report
            json_report = report_gen.generate_json_report()
            json_file = io.BytesIO(json_report.encode('utf-8'))
            json_file.name = f"vulnerability_report_{int(datetime.now().timestamp())}.json"
            
            # Generate HTML report
            html_report = report_gen.generate_html_report()
            html_file = io.BytesIO(html_report.encode('utf-8'))
            html_file.name = f"vulnerability_report_{int(datetime.now().timestamp())}.html"
            
            # Send files
            await update.message.reply_document(
                document=json_file,
                caption="📄 **JSON Report** - Machine-readable vulnerability data"
            )
            
            await update.message.reply_document(
                document=html_file,
                caption="📄 **HTML Report** - Human-friendly vulnerability report"
            )
            
        except Exception as e:
            await update.message.reply_text(f"❌ Failed to generate reports: {str(e)}")
    
    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Check scan status"""
        user_id = update.effective_user.id
        
        if user_id in self.active_scans:
            await update.message.reply_text("🔍 You have an active scan running. Please wait for completion.")
        else:
            await update.message.reply_text("ℹ️ No active scans. Use /scan to start a new scan.")
    
    async def stop_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Stop current scan"""
        user_id = update.effective_user.id
        
        if user_id in self.active_scans:
            del self.active_scans[user_id]
            if user_id in self.user_sessions:
                del self.user_sessions[user_id]
            await update.message.reply_text("🛑 Scan stopped successfully.")
        else:
            await update.message.reply_text("ℹ️ No active scan to stop.")
    
    async def attacks_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show detailed attack information from last scan"""
        user_id = update.effective_user.id
        
        # Check if user has recent scan data
        if not hasattr(self, 'last_scan_results') or user_id not in getattr(self, 'last_scan_results', {}):
            await update.message.reply_text(
                "ℹ️ No recent scan data available. Please run /scan first."
            )
            return
        
        results = self.last_scan_results[user_id]
        
        # Generate attack details
        attack_details = self._generate_attack_details(results)
        
        if attack_details:
            await update.message.reply_text(attack_details, parse_mode=ParseMode.MARKDOWN)
        else:
            await update.message.reply_text("ℹ️ No attack data available from the last scan.")
    
    async def exploits_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show successful exploits and extracted data"""
        user_id = update.effective_user.id
        
        if not hasattr(self, 'last_scan_results') or user_id not in getattr(self, 'last_scan_results', {}):
            await update.message.reply_text(
                "ℹ️ No recent scan data available. Please run /scan first."
            )
            return
        
        results = self.last_scan_results[user_id]
        
        # Generate exploit details
        exploit_details = self._generate_exploit_details(results)
        
        if exploit_details:
            await update.message.reply_text(exploit_details, parse_mode=ParseMode.MARKDOWN)
        else:
            await update.message.reply_text("✅ No successful exploits found - target appears secure!")
    
    async def credentials_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show discovered credentials"""
        user_id = update.effective_user.id
        
        if not hasattr(self, 'last_scan_results') or user_id not in getattr(self, 'last_scan_results', {}):
            await update.message.reply_text(
                "ℹ️ No recent scan data available. Please run /scan first."
            )
            return
        
        results = self.last_scan_results[user_id]
        
        # Generate credentials report
        creds_details = self._generate_credentials_report(results)
        
        if creds_details:
            await update.message.reply_text(creds_details, parse_mode=ParseMode.MARKDOWN)
        else:
            await update.message.reply_text("ℹ️ No credentials discovered during scan.")
    
    def _generate_attack_details(self, results: Dict) -> str:
        """Generate detailed attack information"""
        if not hasattr(self, 'attack_results'):
            return ""
        
        attack_info = f"""
🔍 **Attack Details Summary**

**Target:** `{results.get('target_url', 'Unknown')}`
**Target IP:** `{results.get('target_ip', 'Unknown')}`

**Vulnerability-Based Attacks:**
"""
        
        # Count attacks by vulnerability type
        vuln_types = {}
        for vuln in results.get('vulnerabilities', []):
            vuln_type = vuln['type']
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = {'count': 0, 'severity': vuln['severity']}
            vuln_types[vuln_type]['count'] += 1
        
        if vuln_types:
            for vuln_type, info in vuln_types.items():
                severity_emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(info['severity'], '⚪')
                attack_info += f"• {severity_emoji} **{vuln_type}**: {info['count']} attack(s)\n"
        
        # VPS/VDS Attack details
        if hasattr(self, 'vps_attack_summary'):
            attack_info += f"\n**VPS/VDS Attacks:**\n{self.vps_attack_summary}"
        
        # Port-based attacks
        if results.get('open_ports'):
            attack_info += f"\n**Port-Based Attacks:**\n"
            for port in results['open_ports']:
                service = results.get('services', {}).get(port, 'Unknown')
                attack_info += f"• Port {port} ({service}): Service enumeration\n"
        
        return attack_info
    
    def _generate_exploit_details(self, results: Dict) -> str:
        """Generate successful exploit information"""
        exploit_info = f"""
⚔️ **Successful Exploits Report**

**Target:** `{results.get('target_url', 'Unknown')}`
"""
        
        # Check for attack engine results
        if hasattr(self, 'attack_engine_results'):
            attack_results = self.attack_engine_results
            
            exploit_info += f"""
**Attack Statistics:**
• Total Attacks: {attack_results.get('total_attacks', 0)}
• Successful Exploits: {attack_results.get('successful_exploits', 0)}
• Failed Exploits: {attack_results.get('failed_exploits', 0)}
• Success Rate: {(attack_results.get('successful_exploits', 0) / max(attack_results.get('total_attacks', 1), 1)) * 100:.1f}%
"""
            
            # Data extraction results
            if attack_results.get('extracted_data'):
                exploit_info += f"\n**📊 Data Extracted:**\n"
                for i, data in enumerate(attack_results['extracted_data'][:5], 1):
                    exploit_info += f"{i}. `{data[:50]}{'...' if len(data) > 50 else ''}`\n"
            
            # Shells obtained
            if attack_results.get('shells_obtained'):
                exploit_info += f"\n**🐚 Shells Obtained:**\n"
                for shell in attack_results['shells_obtained']:
                    exploit_info += f"• **{shell['type']}**: {shell.get('url', shell.get('status', 'Active'))}\n"
        
        # VPS/VDS exploit results
        if hasattr(self, 'vps_exploit_results'):
            vps_results = self.vps_exploit_results
            if vps_results.get('successful_attacks', 0) > 0:
                exploit_info += f"\n**🚀 VPS/VDS Exploits:**\n"
                exploit_info += f"• Successful Attacks: {vps_results['successful_attacks']}\n"
                
                if vps_results.get('credentials_found'):
                    exploit_info += "• Credentials Found:\n"
                    for cred in vps_results['credentials_found'][:3]:
                        exploit_info += f"  - {cred.get('service', 'Unknown')}: `{cred.get('username', '')}:{cred.get('password', '')}`\n"
        
        return exploit_info
    
    def _generate_credentials_report(self, results: Dict) -> str:
        """Generate credentials discovery report"""
        creds_report = f"""
🔑 **Credentials Discovery Report**

**Target:** `{results.get('target_url', 'Unknown')}`
"""
        
        found_credentials = []
        
        # Attack engine credentials
        if hasattr(self, 'attack_engine_results') and self.attack_engine_results.get('credentials_found'):
            for cred in self.attack_engine_results['credentials_found']:
                found_credentials.append({
                    'source': 'Web Attack',
                    'data': cred.get('data', ''),
                    'location': cred.get('location', 'Unknown')
                })
        
        # VPS/VDS credentials
        if hasattr(self, 'vps_exploit_results') and self.vps_exploit_results.get('credentials_found'):
            for cred in self.vps_exploit_results['credentials_found']:
                found_credentials.append({
                    'source': f"{cred.get('service', 'Unknown')} Service",
                    'data': f"{cred.get('username', '')}:{cred.get('password', '')}",
                    'location': f"Port {cred.get('port', 'Unknown')}"
                })
        
        if found_credentials:
            creds_report += f"\n**📋 Discovered Credentials:**\n"
            for i, cred in enumerate(found_credentials[:10], 1):
                creds_report += f"{i}. **{cred['source']}**\n"
                creds_report += f"   • Data: `{cred['data']}`\n"
                creds_report += f"   • Location: {cred['location']}\n\n"
        
        return creds_report if found_credentials else ""

def main():
    """Main function to run the bot"""
    # Get bot token from environment
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    
    if not bot_token:
        print("❌ Error: TELEGRAM_BOT_TOKEN not found in .env file")
        print("Please add your bot token to the .env file:")
        print("TELEGRAM_BOT_TOKEN=your_bot_token_here")
        return
    
    # Create bot instance
    bot = VulnerabilityTelegramBot()
    
    # Create application
    application = Application.builder().token(bot_token).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", bot.start_command))
    application.add_handler(CommandHandler("help", bot.help_command))
    application.add_handler(CommandHandler("scan", bot.scan_command))
    application.add_handler(CommandHandler("config", bot.config_command))
    application.add_handler(CommandHandler("status", bot.status_command))
    application.add_handler(CommandHandler("stop", bot.stop_command))
    application.add_handler(CommandHandler("attacks", bot.attacks_command))
    application.add_handler(CommandHandler("exploits", bot.exploits_command))
    application.add_handler(CommandHandler("credentials", bot.credentials_command))
    application.add_handler(CallbackQueryHandler(bot.button_callback))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_message))
    
    # Start the bot
    print("🤖 Starting Vulnerability Scanner Telegram Bot...")
    print("🔍 Bot is ready to scan for vulnerabilities!")
    
    # Run the bot
    application.run_polling()

if __name__ == '__main__':
    main()
