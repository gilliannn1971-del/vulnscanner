import asyncio
import time
from typing import Dict, Any, Callable, Optional
from telegram import Update
from telegram.ext import ContextTypes

class TelegramProgressHandler:
    """Handle live progress updates for Telegram bot attacks"""
    
    def __init__(self):
        self.active_messages = {}
        self.progress_data = {}
    
    async def start_progress_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE, operation: str) -> int:
        """Start a progress message and return message ID"""
        initial_text = f"🚀 Starting {operation}...\n\n⏳ Initializing..."
        
        message = await update.message.reply_text(initial_text)
        message_id = message.message_id
        
        self.active_messages[message_id] = {
            'message': message,
            'operation': operation,
            'start_time': time.time(),
            'last_update': time.time()
        }
        
        self.progress_data[message_id] = {
            'current_step': 0,
            'total_steps': 100,
            'current_operation': 'Initializing',
            'completed_operations': [],
            'success_count': 0,
            'failure_count': 0,
            'findings': []
        }
        
        return message_id
    
    async def update_progress(self, message_id: int, progress_percent: int, operation: str, 
                            success_count: int = 0, failure_count: int = 0, findings: list = None):
        """Update progress message with current status"""
        if message_id not in self.active_messages:
            return
        
        if findings is None:
            findings = []
        
        message_obj = self.active_messages[message_id]['message']
        operation_name = self.active_messages[message_id]['operation']
        
        # Update progress data
        self.progress_data[message_id].update({
            'current_step': progress_percent,
            'current_operation': operation,
            'success_count': success_count,
            'failure_count': failure_count
        })
        
        if findings:
            self.progress_data[message_id]['findings'].extend(findings)
        
        # Generate progress bar
        progress_bar = self._generate_progress_bar(progress_percent)
        
        # Calculate elapsed time
        elapsed = time.time() - self.active_messages[message_id]['start_time']
        elapsed_str = f"{int(elapsed//60)}m {int(elapsed%60)}s"
        
        # Build status message
        status_text = f"""🚀 **{operation_name}** - {progress_percent}%

{progress_bar}

📊 **Current Operation:** {operation}
⏱️ **Elapsed Time:** {elapsed_str}

📈 **Results:**
✅ Successful: {success_count}
❌ Failed: {failure_count}
🔍 Total Findings: {len(self.progress_data[message_id]['findings'])}
"""
        
        # Add recent findings
        if self.progress_data[message_id]['findings']:
            recent_findings = self.progress_data[message_id]['findings'][-3:]
            status_text += "\n🎯 **Latest Findings:**\n"
            for finding in recent_findings:
                status_text += f"• {finding}\n"
        
        try:
            # Only update if enough time has passed (avoid rate limiting)
            if time.time() - self.active_messages[message_id]['last_update'] > 2:
                await message_obj.edit_text(status_text, parse_mode='Markdown')
                self.active_messages[message_id]['last_update'] = time.time()
        except Exception:
            pass  # Ignore edit failures (rate limiting, etc.)
    
    async def complete_progress(self, message_id: int, final_results: Dict[str, Any]):
        """Complete progress message with final results"""
        if message_id not in self.active_messages:
            return
        
        message_obj = self.active_messages[message_id]['message']
        operation_name = self.active_messages[message_id]['operation']
        
        elapsed = time.time() - self.active_messages[message_id]['start_time']
        elapsed_str = f"{int(elapsed//60)}m {int(elapsed%60)}s"
        
        # Generate final summary
        final_text = f"""✅ **{operation_name} COMPLETED**

⏱️ **Total Time:** {elapsed_str}
🎯 **Total Attacks:** {final_results.get('total_attacks', 0)}
✅ **Successful Exploits:** {final_results.get('successful_exploits', 0)}
🔑 **Credentials Found:** {len(final_results.get('credentials_found', []))}
🐚 **Shells Obtained:** {len(final_results.get('shells_obtained', []))}
💾 **Databases Compromised:** {len(final_results.get('databases_compromised', []))}

"""
        
        # Add top findings
        if final_results.get('credentials_found'):
            final_text += "🔑 **Credentials Discovered:**\n"
            for cred in final_results['credentials_found'][:5]:
                cred_type = cred.get('type', 'Unknown')
                username = cred.get('username', 'N/A')
                final_text += f"• {cred_type}: {username}:***\n"
        
        if final_results.get('shells_obtained'):
            final_text += "\n🐚 **Shells Obtained:**\n"
            for shell in final_results['shells_obtained'][:3]:
                shell_type = shell.get('type', 'Unknown')
                final_text += f"• {shell_type}\n"
        
        if final_results.get('databases_compromised'):
            final_text += "\n💾 **Database Access:**\n"
            for db in final_results['databases_compromised'][:3]:
                db_type = db.get('type', 'Unknown')
                final_text += f"• {db_type} Database\n"
        
        try:
            await message_obj.edit_text(final_text, parse_mode='Markdown')
        except Exception:
            pass
        
        # Clean up
        del self.active_messages[message_id]
        del self.progress_data[message_id]
    
    def _generate_progress_bar(self, progress_percent: int) -> str:
        """Generate a visual progress bar"""
        filled = int(progress_percent / 5)  # 20 blocks total
        empty = 20 - filled
        
        bar = "🟩" * filled + "⬜" * empty
        return f"{bar} {progress_percent}%"

# Global progress handler instance
telegram_progress = TelegramProgressHandler()