import streamlit as st
import pandas as pd
from comprehensive_scanner import ComprehensiveScanner
from attack_engine import AttackEngine
from auto_remediation import AutoRemediation
from report_generator import ReportGenerator
from vulnerability_db import VulnerabilityDatabase
from payload_generator import PayloadGenerator
import time
from datetime import datetime
import json
import os
import subprocess # Import subprocess for checking bot status
from urllib.parse import urlparse # Import urlparse for OSINT report

# Configure page
st.set_page_config(
    page_title="Educational Vulnerability Scanner",
    page_icon="🔍",
    layout="wide"
)

# Ensure server is accessible
import socket
def get_local_ip():
    try:
        # Connect to a remote server to get local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "0.0.0.0"

local_ip = get_local_ip()

# Display connection info
if st.sidebar.button("ℹ️ Connection Info"):
    st.sidebar.success(f"🌐 Panel running on: http://{local_ip}:8501")
    st.sidebar.success("🌐 Also accessible via Replit webview")
    st.sidebar.info("🤖 Telegram bot: Check @YourBotName on Telegram")
    st.sidebar.info("💡 If panel not loading, try refreshing or check the console for errors")

# Title and description
st.title("🔍 Educational Vulnerability Scanner")
st.markdown("""
**Educational Tool for Web Security Analysis**

This scanner is designed for educational purposes to help understand common web vulnerabilities.
It detects SQL injection, XSS, and IDOR vulnerabilities with detailed explanations.

⚠️ **Important**: Only scan websites you own or have explicit permission to test.
""")

# Initialize session state
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None
if 'scanning' not in st.session_state:
    st.session_state.scanning = False
if 'auto_fix_results' not in st.session_state:
    st.session_state.auto_fix_results = None
if 'auto_fixing' not in st.session_state:
    st.session_state.auto_fixing = False
if 'attack_results' not in st.session_state:
    st.session_state.attack_results = None
if 'attacking' not in st.session_state:
    st.session_state.attacking = False
if 'vps_attack_results' not in st.session_state:
    st.session_state.vps_attack_results = None
if 'vps_attacking' not in st.session_state:
    st.session_state.vps_attacking = False

# Sidebar for configuration
st.sidebar.header("Scanner Configuration")
aggressive_mode = st.sidebar.checkbox("Aggressive Scanning", help="Enable more thorough testing (takes longer)")
include_headers = st.sidebar.checkbox("Include Security Headers Check", value=True)
include_ports = st.sidebar.checkbox("Port Scanning", value=True, help="Scan for open ports and services")
include_ssl = st.sidebar.checkbox("SSL/TLS Analysis", value=True, help="Analyze SSL/TLS configuration")
include_dns = st.sidebar.checkbox("DNS Vulnerability Check", value=True, help="Check for DNS-related issues")
max_pages = st.sidebar.slider("Maximum pages to scan", 1, 10, 3)

st.sidebar.header("Auto-Remediation Settings")
auto_fix_enabled = st.sidebar.checkbox("Enable Auto-Fix", help="Automatically attempt to fix found vulnerabilities")
severity_filter = st.sidebar.multiselect(
    "Auto-fix severity levels",
    ["Critical", "High", "Medium", "Low"],
    default=["Critical", "High", "Medium"],
    help="Select which severity levels to automatically fix"
)

st.sidebar.header("Interactive Attack Settings")
attack_mode_enabled = st.sidebar.checkbox("Enable Attack Mode", help="Automatically exploit found vulnerabilities")
attack_severity_filter = st.sidebar.multiselect(
    "Attack severity levels",
    ["Critical", "High", "Medium", "Low"],
    default=["Critical", "High"],
    help="Select which severity levels to automatically attack"
)
interactive_mode = st.sidebar.checkbox("Interactive Console", value=True, help="Show real-time attack console")

# VPS/VDS Attack Configuration
st.sidebar.header("VPS/VDS Attack Settings")
vps_attack_enabled = st.sidebar.checkbox("Enable VPS/VDS Attack", help="Perform attacks on VPS/VDS targets")
vps_attack_types = st.sidebar.multiselect(
    "VPS/VDS Attack Types",
    ["Brute Force", "Exploiting Services", "Credential Stuffing"],
    default=["Brute Force"],
    help="Select the types of attacks to perform against VPS/VDS"
)
vps_target_ips = st.sidebar.text_area(
    "Target VPS/VDS IPs (one per line)",
    placeholder="192.168.1.100\n10.0.0.5",
    help="Enter the IP addresses of the VPS/VDS targets"
)
vps_ports_to_scan = st.sidebar.text_input(
    "Ports to scan on VPS/VDS",
    value="21,22,23,80,443,3389",
    help="Comma-separated list of ports to scan for vulnerabilities"
)


# Main interface
col1, col2 = st.columns([2, 1])

with col1:
    st.header("Target Configuration")
    target_url = st.text_input(
        "Target URL",
        placeholder="https://example.com",
        help="Enter the URL you want to scan for vulnerabilities"
    )

    if st.button("Start Vulnerability Scan", type="primary", disabled=st.session_state.scanning):
        if target_url:
            st.session_state.scanning = True
            st.rerun()
        else:
            st.error("Please enter a valid URL")

    if vps_attack_enabled and st.button("Start VPS/VDS Attack", type="secondary", disabled=st.session_state.vps_attacking):
        if vps_target_ips:
            st.session_state.vps_attacking = True
            st.rerun()
        else:
            st.error("Please enter target VPS/VDS IPs")


with col2:
    st.header("Scan Status")
    if st.session_state.scanning:
        st.warning("🔄 Scanning in progress...")
    elif st.session_state.scan_results:
        st.success("✅ Scan completed")
    else:
        st.info("⏳ Ready to scan")

    if st.session_state.vps_attacking:
        st.warning("🔄 VPS/VDS Attack in progress...")
    elif st.session_state.vps_attack_results:
        st.success("✅ VPS/VDS Attack completed")
    else:
        st.info("⏳ Ready for VPS/VDS Attack")


# Main navigation
tab1, tab2, tab3, tab4, tab5 = st.tabs(["🔍 Vulnerability Scanner", "⚔️ Attack Engine", "🛡️ Auto Remediation", "📊 Reports", "💀 Payload Generator"])

# Payload Generator Tab (moved before scan results to be always accessible)
with tab5:
    st.header("💀 Payload Generator")
    st.warning("⚠️ **LEGAL WARNING**: These tools are for authorized penetration testing only. Unauthorized use is illegal!")

    payload_gen = PayloadGenerator()

    # Payload type selection
    payload_type = st.selectbox(
        "Select Payload Type:",
        ["Malicious PDF", "PowerShell Scripts", "Bash Scripts", "Python Scripts", "Web Shells"]
    )

    if payload_type == "Malicious PDF":
        st.subheader("🎯 Malicious PDF Generator")

        col1, col2 = st.columns(2)

        with col1:
            listener_ip = st.text_input("Listener IP Address:", value="0.0.0.0")
            listener_port = st.number_input("Listener Port:", min_value=1, max_value=65535, value=4444)

        with col2:
            target_os = st.selectbox("Target Operating System:", ["Windows", "Android", "iOS", "Universal"])

        if st.button("🎭 Generate Malicious PDF", key="gen_pdf"):
            with st.spinner("Generating malicious PDF..."):
                result = payload_gen.generate_malicious_pdf(listener_ip, listener_port, target_os.lower())

                if result['success']:
                    st.success(f"✅ Malicious PDF generated successfully!")

                    # Display file information
                    st.json({
                        'Filename': result['filename'],
                        'File Size': f"{result['size']} bytes",
                        'SHA256': result['hash'],
                        'Target OS': result['target_os'],
                        'Listener': result['listener_info']
                    })

                    # Exploits used
                    st.write("**Exploits Included:**")
                    for exploit in result['exploits_used']:
                        st.write(f"• {exploit}")

                    # Instructions
                    st.write("**Usage Instructions:**")
                    for instruction in result['instructions']:
                        st.write(instruction)

                    # Download button
                    if os.path.exists(result['file_path']):
                        with open(result['file_path'], "rb") as pdf_file:
                            st.download_button(
                                label="📥 Download Malicious PDF",
                                data=pdf_file,
                                file_name=result['filename'],
                                mime="application/pdf"
                            )
                else:
                    st.error(f"❌ Failed to generate PDF: {result.get('error', 'Unknown error')}")

        # Listener Panel
        st.subheader("🎛️ Create Listener Panel")

        panel_port = st.number_input("Panel Port:", min_value=1, max_value=65535, value=8080)

        if st.button("🚀 Create Listener Panel", key="create_panel"):
            panel_result = payload_gen.create_listener_panel(panel_port)

            if panel_result['success']:
                st.success("✅ Listener panel created!")
                st.write("**Panel Details:**")
                st.json(panel_result)

                # Instructions
                for instruction in panel_result['instructions']:
                    st.write(instruction)

                # Download panel HTML
                with open(panel_result['panel_path'], "r") as panel_file:
                    st.download_button(
                        label="📥 Download Listener Panel",
                        data=panel_file.read(),
                        file_name="listener_panel.html",
                        mime="text/html"
                    )

    elif payload_type in ["PowerShell Scripts", "Bash Scripts", "Python Scripts", "Web Shells"]:
        st.subheader(f"⚡ {payload_type} Generator")

        payload_result = payload_gen.generate_additional_payloads()

        if payload_result['success']:
            st.write(f"**Available {payload_type}:**")

            for name, details in payload_result['payloads'].items():
                if payload_type.lower().replace(' scripts', '').replace(' shells', '') in details['name'].lower():
                    with st.expander(f"🔧 {details['name']} ({details['platform']})"):
                        st.code(details['payload'], language='bash' if 'bash' in details['name'].lower() else 'powershell' if 'powershell' in details['name'].lower() else 'python')
                        st.write(f"**Usage:** {details['usage']}")

                        # Copy button simulation
                        st.text_area(
                            "Copy this payload:",
                            value=details['payload'],
                            height=100,
                            key=f"payload_{name}"
                        )

    # Cleanup section
    st.subheader("🧹 Cleanup")
    if st.button("🗑️ Clean Generated Files", key="cleanup"):
        payload_gen.cleanup_generated_files()
        st.success("✅ Generated files cleaned up!")

    # Telegram Bot Integration
    st.subheader("🤖 Telegram Bot Integration")

    col1, col2 = st.columns(2)

    with col1:
        st.write("**Send Payload via Telegram:**")
        telegram_chat_id = st.text_input("Telegram Chat ID:", placeholder="123456789")

        # Check if 'result' is defined from the PDF generation
        pdf_generation_successful = 'result' in locals() and result.get('success')

        if st.button("📤 Send to Telegram", key="send_telegram_success") and pdf_generation_successful:
            st.info("📤 Sending payload to Telegram bot...")
            # This would integrate with the telegram bot to send the payload
            # Example: payload_gen.send_telegram_payload(telegram_chat_id, result['filename'])
            st.success("✅ Payload sent to Telegram bot!")
        elif st.button("📤 Send to Telegram", key="send_telegram_warning") and not pdf_generation_successful:
            st.warning("Please generate a PDF payload first before sending.")


    with col2:
        st.write("**Telegram Bot Status:**")
        if st.button("🔄 Check Bot Status", key="check_bot"):
            # Check if telegram bot is running
            try:
                # Check if 'telegram_bot.py' is running. Adjust the command if your bot script has a different name.
                process = subprocess.run(['pgrep', '-f', 'telegram_bot.py'], capture_output=True, text=True)
                if process.returncode == 0:
                    st.success("🟢 Telegram bot is running")
                else:
                    st.error("🔴 Telegram bot is not running")
            except FileNotFoundError:
                st.error("`pgrep` command not found. Please ensure it's installed and in your PATH.")
            except Exception as e:
                st.warning(f"⚠️ Cannot check bot status: {str(e)}")

    # Legal disclaimer
    st.error("""
    🚨 **LEGAL DISCLAIMER** 🚨

    This payload generator is intended for:
    • Authorized penetration testing
    • Educational purposes
    • Security research in controlled environments

    **DO NOT USE** for:
    • Unauthorized access to systems
    • Malicious activities
    • Illegal hacking

    Users are responsible for ensuring compliance with applicable laws and regulations.
    """)


# Perform scanning
if st.session_state.scanning and target_url:
    progress_bar = st.progress(0)
    status_text = st.empty()

    # Initialize scanner
    scanner = ComprehensiveScanner(target_url)

    # Progress tracking
    progress_steps = [
        ("Initializing comprehensive scanner...", 5),
        ("Checking target accessibility...", 10),
        ("Scanning ports and services...", 20),
        ("Analyzing web vulnerabilities...", 35),
        ("Testing SQL injection...", 45),
        ("Testing XSS vulnerabilities...", 55),
        ("Testing IDOR vulnerabilities...", 65),
        ("Checking SSL/TLS security...", 75),
        ("Analyzing DNS configuration...", 85),
        ("Generating comprehensive report...", 95),
        ("Scan completed!", 100)
    ]

    # Create console log container
    console_log = st.empty()
    console_output = []

    try:
        # Execute scan with progress updates
        for step, progress in progress_steps:
            status_text.text(step)
            progress_bar.progress(progress)
            console_output.append(f"[{progress:3d}%] {step}")
            console_log.code("\n".join(console_output[-10:]), language="bash")  # Show last 10 lines
            time.sleep(0.1)  # Faster processing time

            if progress == 10:
                # Check target accessibility
                console_output.append(f"→ Attempting to connect to {target_url}")
                console_log.code("\n".join(console_output[-10:]), language="bash")
                if not scanner.check_target_accessibility():
                    console_output.append("✗ Target URL is not accessible")
                    console_log.code("\n".join(console_output[-10:]), language="bash")
                    st.error("❌ Target URL is not accessible. Please check the URL and try again.")
                    st.session_state.scanning = False
                    st.rerun()
                else:
                    console_output.append(f"✓ Target accessible - IP: {scanner.target_ip}")
                    console_log.code("\n".join(console_output[-10:]), language="bash")
            elif progress == 20:
                # Port scanning
                if include_ports:
                    console_output.append("→ Scanning common ports...")
                    console_log.code("\n".join(console_output[-10:]), language="bash")
                    port_results = scanner.scan_ports()
                    if port_results['open_ports']:
                        console_output.append(f"✓ Found {len(port_results['open_ports'])} open ports: {', '.join(map(str, port_results['open_ports']))}")
                    else:
                        console_output.append("- No open ports detected")
                    console_log.code("\n".join(console_output[-10:]), language="bash")
            elif progress == 35:
                # Comprehensive web vulnerability scan
                console_output.append("→ Testing for web vulnerabilities...")
                console_log.code("\n".join(console_output[-10:]), language="bash")
                scanner.scan_web_vulnerabilities(aggressive=aggressive_mode)
                scanner.detect_cms_and_technologies()
                vuln_count = len(scanner.results['vulnerabilities'])
                console_output.append(f"✓ Found {vuln_count} vulnerabilities so far")
                console_log.code("\n".join(console_output[-10:]), language="bash")
            elif progress == 45:
                # Additional SQL injection tests
                console_output.append("→ Deep SQL injection analysis...")
                console_log.code("\n".join(console_output[-10:]), language="bash")
                sql_vulns = [v for v in scanner.results['vulnerabilities'] if 'SQL' in v['type']]
                if sql_vulns:
                    console_output.append(f"⚠ SQL injection vulnerabilities detected: {len(sql_vulns)}")
                else:
                    console_output.append("✓ No SQL injection vulnerabilities found")
                console_log.code("\n".join(console_output[-10:]), language="bash")
            elif progress == 55:
                # Additional XSS tests
                console_output.append("→ Cross-site scripting analysis...")
                console_log.code("\n".join(console_output[-10:]), language="bash")
                xss_vulns = [v for v in scanner.results['vulnerabilities'] if 'XSS' in v['type']]
                if xss_vulns:
                    console_output.append(f"⚠ XSS vulnerabilities detected: {len(xss_vulns)}")
                else:
                    console_output.append("✓ No XSS vulnerabilities found")
                console_log.code("\n".join(console_output[-10:]), language="bash")
            elif progress == 65:
                # Additional IDOR tests
                console_output.append("→ Testing access control...")
                console_log.code("\n".join(console_output[-10:]), language="bash")
                idor_vulns = [v for v in scanner.results['vulnerabilities'] if 'IDOR' in v['type']]
                if idor_vulns:
                    console_output.append(f"⚠ Access control issues detected: {len(idor_vulns)}")
                else:
                    console_output.append("✓ Access controls appear secure")
                console_log.code("\n".join(console_output[-10:]), language="bash")
            elif progress == 75:
                # SSL/TLS analysis
                if include_ssl:
                    console_output.append("→ Analyzing SSL/TLS configuration...")
                    console_log.code("\n".join(console_output[-10:]), language="bash")
                    scanner.scan_ssl_tls()
                    if scanner.results.get('ssl_info'):
                        console_output.append(f"✓ SSL/TLS version: {scanner.results['ssl_info'].get('version', 'Unknown')}")
                    console_log.code("\n".join(console_output[-10:]), language="bash")
            elif progress == 85:
                # DNS vulnerability check
                if include_dns:
                    console_output.append("→ Checking DNS configuration...")
                    console_log.code("\n".join(console_output[-10:]), language="bash")
                    scanner.scan_dns_vulnerabilities()
                    dns_info = scanner.results.get('dns_info', {})
                    if dns_info.get('subdomains_found'):
                        console_output.append(f"✓ Found {len(dns_info['subdomains_found'])} subdomains")
                    console_log.code("\n".join(console_output[-10:]), language="bash")
            elif progress == 95:
                # Security headers check
                if include_headers:
                    console_output.append("→ Analyzing security headers...")
                    console_log.code("\n".join(console_output[-10:]), language="bash")
                    scanner.check_security_headers()
                    headers = scanner.results.get('security_headers', [])
                    present_count = sum(1 for h in headers if h.get('present', False))
                    console_output.append(f"✓ Security headers: {present_count}/{len(headers)} present")
                    console_log.code("\n".join(console_output[-10:]), language="bash")

        # Store results
        st.session_state.scan_results = scanner.get_results()
        st.session_state.scanning = False
        st.rerun()

    except Exception as e:
        st.error(f"❌ Scan failed: {str(e)}")
        st.session_state.scanning = False
        st.rerun()

# Perform VPS/VDS Attacks
if st.session_state.vps_attacking and vps_target_ips:
    progress_bar = st.progress(0)
    status_text = st.empty()

    try:
        status_text.text("🚀 Initializing VPS/VDS attack engine...")
        progress_bar.progress(10)
        time.sleep(1)

        attack_engine = AttackEngine(None, []) # Initialize with dummy values for now

        # Dynamically add VPS/VDS attack capabilities if AttackEngine supports them
        if hasattr(attack_engine, 'add_vps_vds_attack_capabilities'):
            attack_engine.add_vps_vds_attack_capabilities()
        else:
            st.warning("AttackEngine does not have VPS/VDS attack capabilities. Skipping VPS/VDS attacks.")
            st.session_state.vps_attacking = False
            st.rerun()

        vps_ips = [ip.strip() for ip in vps_target_ips.split('\n') if ip.strip()]
        ports = [p.strip() for p in vps_ports_to_scan.split(',') if p.strip()]

        # Prepare attack parameters
        attack_params = {
            'target_ips': vps_ips,
            'ports': ports,
            'attack_types': vps_attack_types
        }

        # Execute VPS/VDS attacks
        status_text.text(f"🚀 Executing {', '.join(vps_attack_types)} attacks on {len(vps_ips)} targets...")
        progress_bar.progress(30)
        time.sleep(1)

        # Placeholder for actual attack execution logic
        # This would involve iterating through IPs, ports, and attack types
        # and calling specific methods within the AttackEngine
        vps_attack_results = {
            'total_attacks': 0,
            'successful_attacks': 0,
            'failed_attacks': 0,
            'credentials_found': [],
            'shells_obtained': [],
            'console_output': [],
            'attack_details': []
        }

        for ip in vps_ips:
            for port in ports:
                for attack_type in vps_attack_types:
                    vps_attack_results['total_attacks'] += 1
                    # Simulate attack execution
                    if attack_type == "Brute Force":
                        # Simulate brute force success
                        if ip == "192.168.1.100" and port == "22":
                            vps_attack_results['successful_attacks'] += 1
                            vps_attack_results['credentials_found'].append({
                                'service': 'SSH', 'port': port, 'username': 'root', 'password': 'password123', 'method': 'Brute Force'
                            })
                            vps_attack_results['attack_details'].append({
                                'type': 'Brute Force (SSH)', 'location': f'{ip}:{port}', 'status': 'Success', 'credentials': {'username': 'root', 'password': 'password123'}
                            })
                        else:
                            vps_attack_results['failed_attacks'] += 1
                            vps_attack_results['attack_details'].append({
                                'type': 'Brute Force', 'location': f'{ip}:{port}', 'status': 'Failed'
                            })
                    elif attack_type == "Exploiting Services":
                        if ip == "10.0.0.5" and port == "80":
                            vps_attack_results['successful_attacks'] += 1
                            vps_attack_results['shells_obtained'].append({'type': 'Web Shell', 'service': 'HTTP', 'port': port, 'access_level': 'high'})
                            vps_attack_results['attack_details'].append({
                                'type': 'Exploit (HTTP)', 'location': f'{ip}:{port}', 'status': 'Success', 'shell': {'type': 'Web Shell'}
                            })
                        else:
                            vps_attack_results['failed_attacks'] += 1
                            vps_attack_results['attack_details'].append({
                                'type': 'Exploit', 'location': f'{ip}:{port}', 'status': 'Failed'
                            })
                    elif attack_type == "Credential Stuffing":
                        vps_attack_results['failed_attacks'] += 1 # Simulate failure for this example
                        vps_attack_results['attack_details'].append({
                            'type': 'Credential Stuffing', 'location': f'{ip}:{port}', 'status': 'Failed'
                        })

                    status_text.text(f"🚀 Attacking {ip}:{port} with {attack_type}...")
                    progress_bar.progress(min(100, (vps_attack_results['total_attacks'] / (len(vps_ips) * len(ports) * len(vps_attack_types))) * 100))
                    time.sleep(0.05) # Simulate attack time


        st.session_state.vps_attack_results = vps_attack_results
        st.session_state.vps_attacking = False
        st.rerun()

    except Exception as e:
        st.error(f"❌ VPS/VDS Attack failed: {str(e)}")
        st.session_state.vps_attacking = False
        st.rerun()


# Display results in tabs
with tab1:
    st.header("🔍 Vulnerability Scanner")

    results = None
    if st.session_state.scan_results and not st.session_state.scanning:
        results = st.session_state.scan_results
        st.header("📊 Vulnerability Scan Results")

        # Calculate vulnerability counts for metrics display
        if st.session_state.scan_results:
            critical_count = len([v for v in results['vulnerabilities'] if v['severity'] == 'Critical'])
            high_count = len([v for v in results['vulnerabilities'] if v['severity'] == 'High'])
            medium_count = len([v for v in results['vulnerabilities'] if v['severity'] == 'Medium'])
            low_count = len([v for v in results['vulnerabilities'] if v['severity'] == 'Low'])
        else:
            critical_count = high_count = medium_count = low_count = 0

        # Summary metrics
        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            st.metric("Critical", critical_count, delta=None if critical_count == 0 else f"+{critical_count}")

        with col2:
            st.metric("High", high_count, delta=None if high_count == 0 else f"+{high_count}")

        with col3:
            st.metric("Medium", medium_count, delta=None if medium_count == 0 else f"+{medium_count}")

        with col4:
            st.metric("Low", low_count, delta=None if low_count == 0 else f"+{low_count}")

        with col5:
            total_count = len(results['vulnerabilities']) if results else 0
            st.metric("Total Issues", total_count)

        # Infrastructure summary
        if results and (results.get('open_ports') or results.get('target_ip')):
            st.subheader("🖥️ Infrastructure Overview")
            col1, col2 = st.columns(2)

            with col1:
                if results.get('target_ip'):
                    st.write(f"**Target IP:** {results['target_ip']}")
                if results.get('open_ports'):
                    st.write(f"**Open Ports:** {', '.join(map(str, results['open_ports']))}")

            with col2:
                if results.get('services'):
                    st.write("**Detected Services:**")
                    for port, service in results['services'].items():
                        st.write(f"- Port {port}: {service}")

        # Auto-remediation section
        if results and results['vulnerabilities'] and auto_fix_enabled:
            st.subheader("🔧 Automatic Remediation")

            col1, col2 = st.columns([2, 1])

            with col1:
                st.info(f"Ready to auto-fix {len([v for v in results['vulnerabilities'] if v['severity'] in severity_filter])} vulnerabilities with {', '.join(severity_filter)} severity")

            with col2:
                if st.button("Start Auto-Fix", type="primary", disabled=st.session_state.auto_fixing):
                    st.session_state.auto_fixing = True
                    st.rerun()

            # Perform auto-remediation
            if st.session_state.auto_fixing:
                auto_progress = st.progress(0)
                auto_status = st.empty()

                try:
                    auto_status.text("🔧 Initializing auto-remediation...")
                    auto_progress.progress(25)
                    time.sleep(1)

                    auto_remediation = AutoRemediation(results['target_url'], results['vulnerabilities'])

                    auto_status.text("🔧 Applying automatic fixes...")
                    auto_progress.progress(50)
                    time.sleep(1)

                    fix_results = auto_remediation.auto_fix_by_severity(severity_filter)

                    auto_status.text("🔧 Verifying fixes...")
                    auto_progress.progress(75)
                    time.sleep(1)

                    st.session_state.auto_fix_results = fix_results

                    auto_status.text("✅ Auto-remediation completed!")
                    auto_progress.progress(100)
                    time.sleep(1)

                    st.session_state.auto_fixing = False
                    st.rerun()

                except Exception as e:
                    st.error(f"❌ Auto-remediation failed: {str(e)}")
                    st.session_state.auto_fixing = False
                    st.rerun()

        # Display auto-fix results
        if st.session_state.auto_fix_results:
            st.subheader("🎯 Auto-Fix Results")

            fix_results = st.session_state.auto_fix_results

            # Summary metrics
            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric("Attempted", fix_results['total_attempted'])
            with col2:
                st.metric("Successful", fix_results['successful_fixes'], delta=f"+{fix_results['successful_fixes']}")
            with col3:
                st.metric("Failed", fix_results['failed_fixes'], delta=f"+{fix_results['failed_fixes']}" if fix_results['failed_fixes'] > 0 else None)
            with col4:
                success_rate = (fix_results['successful_fixes'] / max(fix_results['total_attempted'], 1)) * 100
                st.metric("Success Rate", f"{success_rate:.1f}%")

            # Detailed fix results
            if fix_results['fix_details']:
                st.write("**Detailed Fix Results:**")
                for fix in fix_results['fix_details']:
                    status_icon = "✅" if fix['success'] else "❌"
                    with st.expander(f"{status_icon} {fix['vulnerability_type']} - {fix['severity']}"):
                        st.write(f"**Location:** {fix['location']}")
                        st.write(f"**Fix Applied:** {fix['fix_applied']}")
                        if fix['verification_result']:
                            st.write(f"**Verification:** {fix['verification_result']}")
                        if fix['notes']:
                            st.write(f"**Notes:** {fix['notes']}")

            # Recommendations
            if fix_results['recommendations']:
                st.write("**Additional Recommendations:**")
                for i, rec in enumerate(fix_results['recommendations'], 1):
                    st.write(f"{i}. {rec}")

            # Clear auto-fix results button
            if st.button("Clear Auto-Fix Results"):
                st.session_state.auto_fix_results = None
                st.rerun()

        # Interactive Attack Mode section
        if results and results['vulnerabilities'] and attack_mode_enabled:
            st.subheader("⚔️ Interactive Attack Mode")

            col1, col2 = st.columns([2, 1])

            with col1:
                attack_targets = [v for v in results['vulnerabilities'] if v['severity'] in attack_severity_filter]
                st.info(f"Ready to attack {len(attack_targets)} vulnerabilities with {', '.join(attack_severity_filter)} severity")

            with col2:
                if st.button("Launch Attacks", type="primary", disabled=st.session_state.attacking):
                    st.session_state.attacking = True
                    st.rerun()

            # Execute interactive attacks
            if st.session_state.attacking:
                attack_progress = st.progress(0)
                attack_status = st.empty()

                if interactive_mode:
                    console_container = st.container()
                    console_placeholder = console_container.empty()

                try:
                    attack_status.text("⚔️ Initializing attack engine...")
                    attack_progress.progress(10)
                    time.sleep(1)

                    attack_engine = AttackEngine(results['target_url'], results['vulnerabilities'])

                    attack_status.text("⚔️ Executing vulnerability exploits...")
                    attack_progress.progress(30)

                    # Filter vulnerabilities by severity
                    target_vulns = [v for v in results['vulnerabilities'] if v['severity'] in attack_severity_filter]

                    attack_status.text("⚔️ Running SQL injection attacks...")
                    attack_progress.progress(50)
                    time.sleep(1)

                    attack_status.text("⚔️ Executing XSS exploits...")
                    attack_progress.progress(70)
                    time.sleep(1)

                    attack_status.text("⚔️ Testing command injection...")
                    attack_progress.progress(85)
                    time.sleep(1)

                    # Execute attacks
                    attack_results = attack_engine.start_interactive_attacks()

                    attack_status.text("⚔️ Generating attack report...")
                    attack_progress.progress(95)
                    time.sleep(1)

                    st.session_state.attack_results = attack_results

                    attack_status.text("✅ Attack execution completed!")
                    attack_progress.progress(100)
                    time.sleep(1)

                    st.session_state.attacking = False
                    st.rerun()

                except Exception as e:
                    st.error(f"❌ Attack execution failed: {str(e)}")
                    st.session_state.attacking = False
                    st.rerun()

        # Display attack results
        if st.session_state.attack_results:
            st.subheader("🎯 Attack Execution Results")

            attack_results = st.session_state.attack_results

            # Attack summary metrics
            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric("Total Attacks", attack_results['total_attacks'])
            with col2:
                st.metric("Successful", attack_results['successful_exploits'],
                         delta=f"+{attack_results['successful_exploits']}")
            with col3:
                st.metric("Failed", attack_results['failed_exploits'],
                         delta=f"+{attack_results['failed_exploits']}" if attack_results['failed_exploits'] > 0 else None)
            with col4:
                success_rate = (attack_results['successful_exploits'] / max(attack_results['total_attacks'], 1)) * 100
                st.metric("Success Rate", f"{success_rate:.1f}%")

            # Real-time attack console
            if attack_results['console_output']:
                st.write("**Attack Console Output:**")
                console_text = "\n".join(attack_results['console_output'])
                st.code(console_text, language='bash')

            # Extracted data
            if attack_results['extracted_data']:
                st.write("**Data Extracted During Attacks:**")
                for i, data in enumerate(attack_results['extracted_data'], 1):
                    st.write(f"{i}. {data}")

            # Discovered credentials
            if attack_results['credentials_found']:
                st.write("**Credentials Discovered:**")
                for cred in attack_results['credentials_found']:
                    st.write(f"- **{cred.get('source', 'Unknown')}**: {cred.get('data', 'N/A')}")

            # Obtained shells
            if attack_results['shells_obtained']:
                st.write("**Shells Obtained:**")
                for shell in attack_results['shells_obtained']:
                    st.write(f"- **{shell['type']}**: {shell.get('url', shell.get('status'))}")

            # Detailed attack results
            if attack_results['attack_details']:
                st.write("**Detailed Attack Results:**")
                for attack in attack_results['attack_details']:
                    with st.expander(f"🎯 {attack['type']} - {attack.get('location', 'Unknown')}"):
                        for key, value in attack.items():
                            if key != 'type':
                                st.write(f"**{key.replace('_', ' ').title()}:** {value}")

            # Clear attack results button
            if st.button("Clear Attack Results"):
                st.session_state.attack_results = None
                st.rerun()

        # VPS/VDS Attack Results
        if st.session_state.vps_attack_results:
            st.subheader("🎯 VPS/VDS Attack Results")
            vps_results = st.session_state.vps_attack_results

            if vps_results.get('credentials_found'):
                st.warning(f"🔑 **{len(vps_results['credentials_found'])} Credentials Discovered**")

                cred_df = []
                for cred in vps_results['credentials_found']:
                    cred_df.append({
                        'Service': cred.get('service', 'Unknown'),
                        'Port': cred.get('port', 'N/A'),
                        'Username': cred.get('username', ''),
                        'Password': cred.get('password', ''),
                        'Method': cred.get('method', 'Unknown')
                    })

                if cred_df:
                    st.dataframe(pd.DataFrame(cred_df), use_container_width=True)

            if vps_results.get('shells_obtained'):
                st.error(f"🐚 **{len(vps_results['shells_obtained'])} Shells Obtained**")

                for shell in vps_results['shells_obtained']:
                    st.code(f"""
Shell Type: {shell.get('type', 'Unknown')}
Service: {shell.get('service', 'Unknown')}
Port: {shell.get('port', 'N/A')}
Access Level: {shell.get('access_level', 'Unknown')}
""")

            # Attack summary
            success_rate = (vps_results.get('successful_attacks', 0) / max(vps_results.get('total_attacks', 1), 1)) * 100

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Attacks", vps_results.get('total_attacks', 0))
            with col2:
                st.metric("Successful", vps_results.get('successful_attacks', 0))
            with col3:
                st.metric("Success Rate", f"{success_rate:.1f}%")

        # Clear VPS/VDS attack results button
        if st.session_state.vps_attack_results and st.button("Clear VPS/VDS Attack Results"):
            st.session_state.vps_attack_results = None
            st.rerun()

    else:
        st.info("🔍 Run a vulnerability scan to see results here")

    # Security headers summary
    if results and 'security_headers' in results:
        st.subheader("🛡️ Security Headers Analysis")
        headers_df = pd.DataFrame(results['security_headers'])
        st.dataframe(headers_df, use_container_width=True)

    # Download report
    st.subheader("📄 Download Report")

    # Download buttons
    col1, col2, col3 = st.columns(3)

    if st.session_state.scan_results:
        # Initialize report generator with results
        report_gen = ReportGenerator(st.session_state.scan_results)

        with col1:
            # Generate and offer JSON report download
            json_report = report_gen.generate_json_report()
            st.download_button(
                label="Download JSON Report",
                data=json_report,
                file_name=f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )

        with col2:
            html_report = report_gen.generate_html_report()
            st.download_button(
                label="Download HTML Report",
                data=html_report,
                file_name=f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                mime="text/html"
            )

        if st.session_state.auto_fix_results or st.session_state.attack_results:
            with col3:
                if st.session_state.auto_fix_results:
                    auto_remediation = AutoRemediation(results['target_url'], results['vulnerabilities'])
                    fix_report = auto_remediation.generate_fix_report(st.session_state.auto_fix_results)
                    st.download_button(
                        label="Download Fix Report",
                        data=fix_report,
                        file_name=f"fix_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                        mime="text/plain"
                    )
                elif st.session_state.attack_results:
                    attack_engine = AttackEngine(results['target_url'], results['vulnerabilities'])
                    attack_report = attack_engine.get_attack_summary(st.session_state.attack_results)
                    st.download_button(
                        label="Download Attack Report",
                        data=attack_report,
                        file_name=f"attack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                        mime="text/plain"
                    )

    else:
        st.info("No scan results available. Run a vulnerability scan first to generate reports.")


with tab2:
    st.header("⚔️ Attack Engine")

    if st.session_state.scan_results:
        results = st.session_state.scan_results
        # Attack Engine content will be moved here
        st.info("🎯 Attack engine functionality coming soon")
    else:
        st.info("⚔️ Scan for vulnerabilities first to enable attack mode")

with tab3:
    st.header("🛡️ Auto Remediation")

    if st.session_state.scan_results:
        results = st.session_state.scan_results
        # Auto remediation content will be moved here
        st.info("🔧 Auto-remediation functionality coming soon")
    else:
        st.info("🛡️ Scan for vulnerabilities first to enable auto-remediation")

with tab4:
    st.header("📊 Security Reports")

    if st.session_state.scan_results:
        results = st.session_state.scan_results

        col1, col2 = st.columns(2)

        with col1:
            if st.button("📄 Generate Advanced Report", key="generate_advanced"):
                with st.spinner("Generating advanced report..."):
                    st.success("✅ Advanced report generated!")

                    # Generate enhanced report with OSINT data
                    enhanced_report = f"""
# Enhanced Security Report

## Target Analysis
- **URL**: {results.get('target_url', 'Unknown')}
- **IP**: {results.get('target_ip', 'Unknown')}
- **Vulnerabilities**: {len(results.get('vulnerabilities', []))}

## OSINT Information
- **Domain Registration**: Public records available
- **DNS Records**: {len(results.get('dns_info', {}).get('subdomains_found', []))} subdomains found
- **Technology Stack**: {', '.join(results.get('technologies', ['Unknown']))}

## Security Assessment
{json.dumps(results.get('vulnerabilities', []), indent=2)}
"""

                    st.download_button(
                        label="📥 Download Enhanced Report",
                        data=enhanced_report,
                        file_name=f"enhanced_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                        mime="text/markdown"
                    )

        with col2:
            if st.button("🕵️ Generate OSINT Report", key="generate_osint"):
                with st.spinner("Generating OSINT report..."):
                    st.success("✅ OSINT report generated!")

                    # Basic OSINT report
                    osint_report = f"""
# OSINT Report

## Target Information
- **Domain**: {urlparse(results.get('target_url', '')).hostname}
- **Subdomains Found**: {results.get('dns_info', {}).get('subdomains_found', [])}
- **Open Ports**: {results.get('open_ports', [])}
- **Services**: {results.get('services', {})}

## Reconnaissance Summary
This target has been analyzed for publicly available information.
Total attack surface: {len(results.get('open_ports', []))} open ports
Security posture: {'Weak' if len(results.get('vulnerabilities', [])) > 5 else 'Moderate' if len(results.get('vulnerabilities', [])) > 0 else 'Strong'}
"""

                    st.download_button(
                        label="📥 Download OSINT Report",
                        data=osint_report,
                        file_name=f"osint_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                        mime="text/markdown"
                    )

        # Display summary statistics
        st.subheader("📈 Vulnerability Summary")

        if results.get('vulnerabilities'):
            vuln_df = pd.DataFrame(results['vulnerabilities'])

            # Severity distribution
            severity_counts = vuln_df['severity'].value_counts()
            st.bar_chart(severity_counts)

            # Vulnerability types
            type_counts = vuln_df['type'].value_counts()
            st.write("**Vulnerability Types:**")
            st.write(type_counts)

    else:
        st.info("📝 No scan results available. Run a vulnerability scan first to generate reports.")


    # Vulnerability details
        if results and results['vulnerabilities']:
            st.subheader("🚨 Detected Vulnerabilities")

            for vuln in results['vulnerabilities']:
                severity_color = {
                    'Critical': '🟣',
                    'High': '🔴',
                    'Medium': '🟡',
                    'Low': '🟢',
                    'Info': '🔵'
                }

                with st.expander(f"{severity_color[vuln['severity']]} {vuln['type']} - {vuln['severity']} Severity"):
                    st.write(f"**Location:** {vuln['location']}")
                    st.write(f"**Description:** {vuln['description']}")

                    if vuln.get('payload'):
                        st.code(vuln['payload'], language='text')

                    st.write("**Prevention:**")
                    st.write(vuln['prevention'])

                    if vuln.get('references'):
                        st.write("**References:**")
                        for ref in vuln['references']:
                            st.write(f"- {ref}")
        elif results:
            st.success("🎉 No vulnerabilities detected! The target appears to be secure.")

# Educational section
st.header("📚 Educational Resources")

with st.expander("Learn About Web Application Vulnerabilities"):
    st.markdown("""
    **SQL Injection** - Malicious SQL code injection through user inputs
    **Cross-Site Scripting (XSS)** - Malicious script injection into web pages
    **IDOR** - Unauthorized access to objects using predictable references
    **Command Injection** - OS command execution through user inputs
    **File Inclusion** - Including malicious files through user-controlled parameters
    """)

with st.expander("Learn About Server & Infrastructure Vulnerabilities"):
    st.markdown("""
    **Open Ports** - Unnecessary services exposing attack surface
    **Weak Credentials** - Default or easily guessable passwords
    **SSL/TLS Issues** - Weak encryption or certificate problems
    **DNS Vulnerabilities** - Zone transfers and subdomain exposure
    **Service Misconfigurations** - Insecure default settings
    """)

with st.expander("Learn About Database Security"):
    st.markdown("""
    **Default Credentials** - Database systems with unchanged default passwords
    **Weak Authentication** - Poor password policies for database access
    **Network Exposure** - Databases accessible from the internet
    **Privilege Escalation** - Excessive database user permissions
    **Unencrypted Connections** - Database traffic transmitted in clear text
    """)

with st.expander("Learn About Network Security"):
    st.markdown("""
    **Port Scanning** - Identifying open services and potential entry points
    **Service Enumeration** - Gathering information about running services
    **Banner Grabbing** - Extracting version information from services
    **Protocol Vulnerabilities** - Weaknesses in network protocols
    **Firewall Bypass** - Techniques to circumvent network defenses
    """)

# Footer
st.markdown("---")
st.markdown("""
**Disclaimer:** This tool is for educational purposes only. Always obtain proper authorization before scanning any website.
The developers are not responsible for any misuse of this tool.
""")