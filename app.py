import streamlit as st
import pandas as pd
from comprehensive_scanner import ComprehensiveScanner
from report_generator import ReportGenerator
from auto_remediation import AutoRemediation
from attack_engine import AttackEngine
import time

# Configure page
st.set_page_config(
    page_title="Educational Vulnerability Scanner",
    page_icon="🔍",
    layout="wide"
)

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

with col2:
    st.header("Scan Status")
    if st.session_state.scanning:
        st.warning("🔄 Scanning in progress...")
    elif st.session_state.scan_results:
        st.success("✅ Scan completed")
    else:
        st.info("⏳ Ready to scan")

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
    
    try:
        # Execute scan with progress updates
        for step, progress in progress_steps:
            status_text.text(step)
            progress_bar.progress(progress)
            time.sleep(0.5)  # Faster processing time
            
            if progress == 10:
                # Check target accessibility
                if not scanner.check_target_accessibility():
                    st.error("❌ Target URL is not accessible. Please check the URL and try again.")
                    st.session_state.scanning = False
                    st.rerun()
            elif progress == 20:
                # Port scanning
                if include_ports:
                    scanner.scan_ports()
            elif progress == 35:
                # Comprehensive web vulnerability scan
                scanner.scan_web_vulnerabilities(aggressive=aggressive_mode)
                scanner.detect_cms_and_technologies()
            elif progress == 45:
                # Additional SQL injection tests
                pass  # Already included in web vulnerabilities
            elif progress == 55:
                # Additional XSS tests
                pass  # Already included in web vulnerabilities
            elif progress == 65:
                # Additional IDOR tests
                pass  # Already included in web vulnerabilities
            elif progress == 75:
                # SSL/TLS analysis
                if include_ssl:
                    scanner.scan_ssl_tls()
            elif progress == 85:
                # DNS vulnerability check
                if include_dns:
                    scanner.scan_dns_vulnerabilities()
            elif progress == 95:
                # Security headers check
                if include_headers:
                    scanner.check_security_headers()
        
        # Store results
        st.session_state.scan_results = scanner.get_results()
        st.session_state.scanning = False
        st.rerun()
        
    except Exception as e:
        st.error(f"❌ Scan failed: {str(e)}")
        st.session_state.scanning = False
        st.rerun()

# Display results
if st.session_state.scan_results and not st.session_state.scanning:
    st.header("📊 Vulnerability Scan Results")
    
    results = st.session_state.scan_results
    report_gen = ReportGenerator(results)
    
    # Summary metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        critical_count = len([v for v in results['vulnerabilities'] if v['severity'] == 'Critical'])
        st.metric("Critical", critical_count, delta=None if critical_count == 0 else f"+{critical_count}")
    
    with col2:
        high_count = len([v for v in results['vulnerabilities'] if v['severity'] == 'High'])
        st.metric("High", high_count, delta=None if high_count == 0 else f"+{high_count}")
    
    with col3:
        medium_count = len([v for v in results['vulnerabilities'] if v['severity'] == 'Medium'])
        st.metric("Medium", medium_count, delta=None if medium_count == 0 else f"+{medium_count}")
    
    with col4:
        low_count = len([v for v in results['vulnerabilities'] if v['severity'] == 'Low'])
        st.metric("Low", low_count, delta=None if low_count == 0 else f"+{low_count}")
    
    with col5:
        total_count = len(results['vulnerabilities'])
        st.metric("Total Issues", total_count)
    
    # Infrastructure summary
    if results.get('open_ports') or results.get('target_ip'):
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
    if results['vulnerabilities'] and auto_fix_enabled:
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
    if results['vulnerabilities'] and attack_mode_enabled:
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

    # Vulnerability details
    if results['vulnerabilities']:
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
    else:
        st.success("🎉 No vulnerabilities detected! The target appears to be secure.")
    
    # Security headers summary
    if 'security_headers' in results:
        st.subheader("🛡️ Security Headers Analysis")
        headers_df = pd.DataFrame(results['security_headers'])
        st.dataframe(headers_df, width='stretch')
    
    # Download report
    st.subheader("📄 Download Report")
    
    if st.session_state.auto_fix_results:
        col1, col2, col3 = st.columns(3)
    else:
        col1, col2 = st.columns(2)
        col3 = None
    
    with col1:
        json_report = report_gen.generate_json_report()
        st.download_button(
            label="Download JSON Report",
            data=json_report,
            file_name=f"vulnerability_report_{int(time.time())}.json",
            mime="application/json"
        )
    
    with col2:
        html_report = report_gen.generate_html_report()
        st.download_button(
            label="Download HTML Report",
            data=html_report,
            file_name=f"vulnerability_report_{int(time.time())}.html",
            mime="text/html"
        )
    
    if col3 and (st.session_state.auto_fix_results or st.session_state.attack_results):
        with col3:
            if st.session_state.auto_fix_results:
                auto_remediation = AutoRemediation(results['target_url'], results['vulnerabilities'])
                fix_report = auto_remediation.generate_fix_report(st.session_state.auto_fix_results)
                st.download_button(
                    label="Download Fix Report",
                    data=fix_report,
                    file_name=f"auto_fix_report_{int(time.time())}.txt",
                    mime="text/plain"
                )
            elif st.session_state.attack_results:
                attack_engine = AttackEngine(results['target_url'], results['vulnerabilities'])
                attack_report = attack_engine.get_attack_summary(st.session_state.attack_results)
                st.download_button(
                    label="Download Attack Report",
                    data=attack_report,
                    file_name=f"attack_report_{int(time.time())}.txt",
                    mime="text/plain"
                )

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
