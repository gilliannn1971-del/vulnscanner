
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import pandas as pd
from typing import Dict, List, Any

class AttackTimelineVisualizer:
    """Create interactive attack timeline and visualizations"""
    
    def __init__(self):
        self.attack_events = []
        self.timeline_data = []
        
    def add_attack_event(self, event_type: str, description: str, 
                        severity: str, success: bool, timestamp: datetime = None):
        """Add attack event to timeline"""
        
        if timestamp is None:
            timestamp = datetime.now()
            
        event = {
            'timestamp': timestamp,
            'event_type': event_type,
            'description': description,
            'severity': severity,
            'success': success,
            'id': len(self.attack_events)
        }
        
        self.attack_events.append(event)
        
    def create_interactive_timeline(self) -> go.Figure:
        """Create interactive Plotly timeline"""
        
        if not self.attack_events:
            return None
            
        # Prepare data for timeline
        df = pd.DataFrame(self.attack_events)
        
        # Color mapping for severity
        color_map = {
            'Critical': '#FF0000',
            'High': '#FF6600', 
            'Medium': '#FFAA00',
            'Low': '#00AA00',
            'Info': '#0066CC'
        }
        
        # Shape mapping for success/failure
        symbol_map = {
            True: 'circle',
            False: 'x'
        }
        
        fig = go.Figure()
        
        # Add events to timeline
        for severity in color_map.keys():
            severity_data = df[df['severity'] == severity]
            
            if not severity_data.empty:
                fig.add_trace(go.Scatter(
                    x=severity_data['timestamp'],
                    y=severity_data['event_type'],
                    mode='markers+text',
                    marker=dict(
                        color=color_map[severity],
                        size=12,
                        symbol=[symbol_map[success] for success in severity_data['success']]
                    ),
                    text=severity_data['description'],
                    textposition="top center",
                    name=f'{severity} Severity',
                    hovertemplate='<b>%{y}</b><br>' +
                                  'Time: %{x}<br>' +
                                  'Description: %{text}<br>' +
                                  '<extra></extra>'
                ))
        
        fig.update_layout(
            title='Security Attack Timeline',
            xaxis_title='Time',
            yaxis_title='Attack Type',
            hovermode='closest',
            showlegend=True,
            height=600
        )
        
        return fig
    
    def create_attack_heatmap(self, results: Dict[str, Any]) -> go.Figure:
        """Create vulnerability heatmap"""
        
        vulnerabilities = results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return None
            
        # Group vulnerabilities by type and severity
        vuln_matrix = {}
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            severity = vuln.get('severity', 'Info')
            
            if vuln_type not in vuln_matrix:
                vuln_matrix[vuln_type] = {s: 0 for s in severity_order}
            
            vuln_matrix[vuln_type][severity] += 1
        
        # Convert to DataFrame for heatmap
        vuln_types = list(vuln_matrix.keys())
        heatmap_data = []
        
        for vuln_type in vuln_types:
            row = [vuln_matrix[vuln_type][severity] for severity in severity_order]
            heatmap_data.append(row)
        
        fig = go.Figure(data=go.Heatmap(
            z=heatmap_data,
            x=severity_order,
            y=vuln_types,
            colorscale='Reds',
            text=heatmap_data,
            texttemplate="%{text}",
            textfont={"size": 12},
            hovertemplate='Vulnerability: %{y}<br>' +
                          'Severity: %{x}<br>' +
                          'Count: %{z}<br>' +
                          '<extra></extra>'
        ))
        
        fig.update_layout(
            title='Vulnerability Heatmap by Type and Severity',
            xaxis_title='Severity Level',
            yaxis_title='Vulnerability Type',
            height=400
        )
        
        return fig
    
    def create_attack_flow_diagram(self, attack_chains: List[Dict]) -> go.Figure:
        """Create attack flow diagram showing chaining"""
        
        if not attack_chains:
            return None
            
        # Create a network-style diagram
        fig = go.Figure()
        
        # Sample attack flow - this would be based on actual attack chain data
        attack_flow = [
            {'step': 1, 'attack': 'Reconnaissance', 'x': 0, 'y': 0},
            {'step': 2, 'attack': 'SQL Injection', 'x': 1, 'y': 0},
            {'step': 3, 'attack': 'Credential Extraction', 'x': 2, 'y': 0},
            {'step': 4, 'attack': 'Privilege Escalation', 'x': 3, 'y': 0},
            {'step': 5, 'attack': 'System Compromise', 'x': 4, 'y': 0}
        ]
        
        # Add nodes
        fig.add_trace(go.Scatter(
            x=[step['x'] for step in attack_flow],
            y=[step['y'] for step in attack_flow],
            mode='markers+text',
            marker=dict(size=20, color='red'),
            text=[step['attack'] for step in attack_flow],
            textposition="bottom center",
            name='Attack Steps'
        ))
        
        # Add connecting lines
        for i in range(len(attack_flow) - 1):
            fig.add_shape(
                type="line",
                x0=attack_flow[i]['x'], y0=attack_flow[i]['y'],
                x1=attack_flow[i+1]['x'], y1=attack_flow[i+1]['y'],
                line=dict(color="red", width=2, dash="dash")
            )
        
        fig.update_layout(
            title='Attack Chain Flow',
            showlegend=False,
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=300
        )
        
        return fig
    
    def create_risk_dashboard(self, results: Dict[str, Any]) -> Dict[str, go.Figure]:
        """Create comprehensive risk dashboard"""
        
        dashboard = {}
        
        # Risk score gauge
        vulnerabilities = results.get('vulnerabilities', [])
        risk_score = self._calculate_risk_score(vulnerabilities)
        
        gauge_fig = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = risk_score,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Overall Risk Score"},
            delta = {'reference': 50},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkred"},
                'steps': [
                    {'range': [0, 25], 'color': "lightgreen"},
                    {'range': [25, 50], 'color': "yellow"},
                    {'range': [50, 75], 'color': "orange"},
                    {'range': [75, 100], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        
        dashboard['risk_gauge'] = gauge_fig
        
        # Vulnerability distribution pie chart
        if vulnerabilities:
            severity_counts = {}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            pie_fig = px.pie(
                values=list(severity_counts.values()),
                names=list(severity_counts.keys()),
                title="Vulnerability Distribution by Severity",
                color_discrete_map={
                    'Critical': '#FF0000',
                    'High': '#FF6600',
                    'Medium': '#FFAA00', 
                    'Low': '#00AA00',
                    'Info': '#0066CC'
                }
            )
            
            dashboard['severity_distribution'] = pie_fig
        
        # Attack success rate over time
        if self.attack_events:
            df = pd.DataFrame(self.attack_events)
            success_rate = df.groupby(df['timestamp'].dt.hour)['success'].mean() * 100
            
            success_fig = px.line(
                x=success_rate.index,
                y=success_rate.values,
                title="Attack Success Rate Over Time",
                labels={'x': 'Hour', 'y': 'Success Rate (%)'}
            )
            
            dashboard['success_rate'] = success_fig
        
        return dashboard
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate overall risk score based on vulnerabilities"""
        
        if not vulnerabilities:
            return 0
        
        severity_weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 2,
            'Info': 1
        }
        
        total_score = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Info')
            total_score += severity_weights.get(severity, 1)
        
        # Normalize to 0-100 scale
        max_possible = len(vulnerabilities) * 10
        risk_score = min((total_score / max_possible) * 100, 100) if max_possible > 0 else 0
        
        return round(risk_score, 1)
    
    def render_streamlit_dashboard(self, results: Dict[str, Any]):
        """Render complete dashboard in Streamlit"""
        
        st.header("🎯 Advanced Attack Analytics Dashboard")
        
        # Create timeline
        timeline_fig = self.create_interactive_timeline()
        if timeline_fig:
            st.subheader("📊 Attack Timeline")
            st.plotly_chart(timeline_fig, use_container_width=True)
        
        # Create risk dashboard
        dashboard_figs = self.create_risk_dashboard(results)
        
        if dashboard_figs:
            col1, col2 = st.columns(2)
            
            with col1:
                if 'risk_gauge' in dashboard_figs:
                    st.plotly_chart(dashboard_figs['risk_gauge'], use_container_width=True)
            
            with col2:
                if 'severity_distribution' in dashboard_figs:
                    st.plotly_chart(dashboard_figs['severity_distribution'], use_container_width=True)
            
            if 'success_rate' in dashboard_figs:
                st.plotly_chart(dashboard_figs['success_rate'], use_container_width=True)
        
        # Create heatmap
        heatmap_fig = self.create_attack_heatmap(results)
        if heatmap_fig:
            st.subheader("🔥 Vulnerability Heatmap")
            st.plotly_chart(heatmap_fig, use_container_width=True)
        
        # Attack statistics
        if results.get('vulnerabilities'):
            st.subheader("📈 Attack Statistics")
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Vulnerabilities", len(results['vulnerabilities']))
            
            with col2:
                critical_count = sum(1 for v in results['vulnerabilities'] 
                                   if v.get('severity') == 'Critical')
                st.metric("Critical Issues", critical_count)
            
            with col3:
                if 'attack_results' in results:
                    success_rate = (results['attack_results'].get('successful_exploits', 0) / 
                                  max(results['attack_results'].get('total_attacks', 1), 1)) * 100
                    st.metric("Success Rate", f"{success_rate:.1f}%")
            
            with col4:
                if 'osint_data' in results:
                    data_points = len(results['osint_data'].get('emails', [])) + \
                                len(results['osint_data'].get('subdomains', []))
                    st.metric("OSINT Data Points", data_points)
