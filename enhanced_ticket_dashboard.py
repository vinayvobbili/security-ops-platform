import streamlit as st
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import altair as alt

# Page config
st.set_page_config(
    page_title="🔐 XSOAR Security Incident Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
        background: linear-gradient(90deg, #1f77b4, #ff7f0e);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }

    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 0.5rem 0;
    }

    .filter-header {
        color: #2E86AB;
        font-weight: 600;
        margin-top: 1rem;
    }

    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #f8f9fa 0%, #e9ecef 100%);
    }
</style>
""", unsafe_allow_html=True)


@st.cache_data(ttl=300)  # Cache for 5 minutes
def load_cached_tickets():
    """Load tickets from the cached JSON file"""
    today_date = datetime.now().strftime('%m-%d-%Y')
    root_directory = Path(__file__).parent
    cache_file = root_directory / "web" / "static" / "charts" / today_date / "past_90_days_tickets.json"

    if not cache_file.exists():
        st.error(f"⚠️ Cache file not found: {cache_file}")
        return []

    try:
        with open(cache_file, 'r') as f:
            tickets = json.load(f)
        return tickets
    except Exception as e:
        st.error(f"❌ Error loading data: {e}")
        return []


def extract_custom_fields(tickets):
    """Extract and flatten custom fields for easier analysis"""
    data = []
    for ticket in tickets:
        base_data = {
            'id': ticket.get('id', ''),
            'name': ticket.get('name', ''),
            'type': ticket.get('type', ''),
            'severity': ticket.get('severity', 0),
            'status': ticket.get('status', 0),
            'owner': ticket.get('owner', ''),
            'created': ticket.get('created', ''),
            'modified': ticket.get('modified', ''),
            'closed': ticket.get('closed', ''),
            'phase': ticket.get('phase', ''),
            'category': ticket.get('category', ''),
            'closeReason': ticket.get('closeReason', ''),
        }

        # Extract custom fields
        custom_fields = ticket.get('CustomFields', {})
        base_data.update({
            'affected_country': custom_fields.get('affectedcountry', 'Unknown'),
            'affected_region': custom_fields.get('affectedregion', 'Unknown'),
            'impact': custom_fields.get('impact', 'Unknown'),
            'security_category': custom_fields.get('securitycategory', 'Unknown'),
            'detection_source': custom_fields.get('detectionsource', 'Unknown'),
            'device_environment': custom_fields.get('deviceenvironment', 'Unknown'),
            'device_type': custom_fields.get('devicetype', 'Unknown'),
            'hostname': custom_fields.get('hostname', 'Unknown'),
            'escalation_state': custom_fields.get('escalationstate', 'Unknown'),
            'contained': custom_fields.get('contained', False),
            'root_cause': custom_fields.get('rootcause', 'Unknown'),
            'device_os': custom_fields.get('deviceos', 'Unknown'),
            'tactic': custom_fields.get('tactic', []),
            'technique': custom_fields.get('technique', []),
            'alert_name': custom_fields.get('alertname', ''),
            'device_tags': custom_fields.get('devicetags', []),
        })

        data.append(base_data)

    df = pd.DataFrame(data)

    # Convert date columns
    for col in ['created', 'modified', 'closed']:
        df[col] = pd.to_datetime(df[col], errors='coerce')

    return df


def create_status_mapping():
    """Create human-readable status mapping"""
    return {
        0: "Pending",
        1: "Active",
        2: "Closed",
        3: "Archive"
    }


def create_severity_mapping():
    """Create human-readable severity mapping"""
    return {
        0: "Unknown",
        1: "Low",
        2: "Medium",
        3: "High",
        4: "Critical"
    }


def main():
    # Header
    st.markdown('<h1 class="main-header">🛡️ Security Incident Command Center</h1>', unsafe_allow_html=True)

    # Load data
    with st.spinner("🔄 Loading security incident data..."):
        tickets = load_cached_tickets()

    if not tickets:
        st.error("❌ No incident data available. Please ensure the cache is populated.")
        return

    df = extract_custom_fields(tickets)
    status_map = create_status_mapping()
    severity_map = create_severity_mapping()

    # Apply mappings
    df['status_name'] = df['status'].map(status_map)
    df['severity_name'] = df['severity'].map(severity_map)

    # Sidebar filters
    st.sidebar.markdown("## 🎛️ Filter Controls")

    # Date range filter
    st.sidebar.markdown('<p class="filter-header">📅 Date Range</p>', unsafe_allow_html=True)
    if df['created'].notna().any():
        min_date = df['created'].min().date()
        max_date = df['created'].max().date()
        date_range = st.sidebar.date_input(
            "Incident Creation Date",
            value=(max_date - timedelta(days=30), max_date),
            min_value=min_date,
            max_value=max_date
        )

    # Geographic filters
    st.sidebar.markdown('<p class="filter-header">🌍 Geographic Filters</p>', unsafe_allow_html=True)

    countries = ['All'] + sorted([str(x) for x in df['affected_country'].unique() if pd.notna(x)])
    selected_country = st.sidebar.selectbox("🇺🇸 Affected Country", countries)

    regions = ['All'] + sorted([str(x) for x in df['affected_region'].unique() if pd.notna(x)])
    selected_region = st.sidebar.selectbox("🌎 Affected Region", regions)

    # Impact and Severity filters
    st.sidebar.markdown('<p class="filter-header">⚠️ Risk Assessment</p>', unsafe_allow_html=True)

    impacts = ['All'] + sorted([str(x) for x in df['impact'].unique() if pd.notna(x)])
    selected_impact = st.sidebar.multiselect("💥 Impact Level", impacts, default=['All'])

    severities = ['All'] + sorted([str(x) for x in df['severity_name'].unique() if pd.notna(x)])
    selected_severities = st.sidebar.multiselect("🚨 Severity", severities, default=['All'])

    # Security category filter
    st.sidebar.markdown('<p class="filter-header">🔍 Security Classification</p>', unsafe_allow_html=True)

    categories = ['All'] + sorted([str(x) for x in df['security_category'].unique() if pd.notna(x)])
    selected_category = st.sidebar.selectbox("🛡️ Security Category", categories)

    # Detection source filter
    sources = ['All'] + sorted([str(x) for x in df['detection_source'].unique() if pd.notna(x)])
    selected_source = st.sidebar.selectbox("🔎 Detection Source", sources)

    # Status filter
    statuses = ['All'] + sorted([str(x) for x in df['status_name'].unique() if pd.notna(x)])
    selected_statuses = st.sidebar.multiselect("📊 Status", statuses, default=['All'])

    # Apply filters
    filtered_df = df.copy()

    if len(date_range) == 2:
        filtered_df = filtered_df[
            (filtered_df['created'].dt.date >= date_range[0]) &
            (filtered_df['created'].dt.date <= date_range[1])
            ]

    if selected_country != 'All':
        filtered_df = filtered_df[filtered_df['affected_country'] == selected_country]

    if selected_region != 'All':
        filtered_df = filtered_df[filtered_df['affected_region'] == selected_region]

    if 'All' not in selected_impact:
        filtered_df = filtered_df[filtered_df['impact'].isin(selected_impact)]

    if 'All' not in selected_severities:
        filtered_df = filtered_df[filtered_df['severity_name'].isin(selected_severities)]

    if selected_category != 'All':
        filtered_df = filtered_df[filtered_df['security_category'] == selected_category]

    if selected_source != 'All':
        filtered_df = filtered_df[filtered_df['detection_source'] == selected_source]

    if 'All' not in selected_statuses:
        filtered_df = filtered_df[filtered_df['status_name'].isin(selected_statuses)]

    # Main dashboard metrics
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        total_incidents = len(filtered_df)
        st.markdown(f"""
        <div class="metric-card">
            <h3>🎫 Total Incidents</h3>
            <h2>{total_incidents:,}</h2>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        critical_incidents = len(filtered_df[filtered_df['severity'] == 4])
        st.markdown(f"""
        <div class="metric-card">
            <h3>🚨 Critical</h3>
            <h2>{critical_incidents:,}</h2>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        open_incidents = len(filtered_df[filtered_df['status'] != 2])
        st.markdown(f"""
        <div class="metric-card">
            <h3>📈 Open</h3>
            <h2>{open_incidents:,}</h2>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        contained_count = len(filtered_df[filtered_df['contained'] == True])
        st.markdown(f"""
        <div class="metric-card">
            <h3>🔒 Contained</h3>
            <h2>{contained_count:,}</h2>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        avg_resolution_time = "N/A"
        if not filtered_df['closed'].isna().all():
            closed_df = filtered_df.dropna(subset=['closed', 'created'])
            if not closed_df.empty:
                resolution_times = (closed_df['closed'] - closed_df['created']).dt.total_seconds() / 3600
                avg_resolution_time = f"{resolution_times.mean():.1f}h"

        st.markdown(f"""
        <div class="metric-card">
            <h3>⏱️ Avg Resolution</h3>
            <h2>{avg_resolution_time}</h2>
        </div>
        """, unsafe_allow_html=True)

    # Charts section
    st.markdown("---")
    st.markdown("## 📊 Security Analytics Dashboard")

    # First row of charts
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 🌍 Geographic Distribution")
        if not filtered_df.empty:
            geo_data = filtered_df['affected_country'].value_counts().head(10)
            fig = px.bar(
                x=geo_data.values,
                y=geo_data.index,
                orientation='h',
                title="Top 10 Affected Countries",
                color=geo_data.values,
                color_continuous_scale="Viridis"
            )
            fig.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.markdown("### 🚨 Severity Distribution")
        if not filtered_df.empty:
            severity_counts = filtered_df['severity_name'].value_counts()
            colors = ['#2E8B57', '#FFD700', '#FF8C00', '#FF4500', '#DC143C']
            fig = px.pie(
                values=severity_counts.values,
                names=severity_counts.index,
                title="Incident Severity Breakdown",
                color_discrete_sequence=colors
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

    # Second row of charts
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 📈 Incident Timeline")
        if not filtered_df.empty and filtered_df['created'].notna().any():
            daily_counts = filtered_df.groupby(filtered_df['created'].dt.date).size().reset_index()
            daily_counts.columns = ['date', 'count']

            fig = px.line(
                daily_counts,
                x='date',
                y='count',
                title='Daily Incident Volume',
                markers=True
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.markdown("### 🔍 Detection Sources")
        if not filtered_df.empty:
            source_counts = filtered_df['detection_source'].value_counts().head(8)
            fig = px.bar(
                x=source_counts.index,
                y=source_counts.values,
                title="Top Detection Sources",
                color=source_counts.values,
                color_continuous_scale="Blues"
            )
            fig.update_layout(height=400, xaxis_tickangle=-45, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

    # Third row - Impact vs Status analysis
    st.markdown("### 💥 Impact vs Status Analysis")
    col1, col2 = st.columns(2)

    with col1:
        if not filtered_df.empty:
            heatmap_data = pd.crosstab(filtered_df['impact'], filtered_df['status_name'])
            fig = px.imshow(
                heatmap_data.values,
                x=heatmap_data.columns,
                y=heatmap_data.index,
                color_continuous_scale="RdYlBu_r",
                title="Impact vs Status Heatmap"
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        if not filtered_df.empty:
            escalation_counts = filtered_df['escalation_state'].value_counts()
            fig = px.funnel(
                y=escalation_counts.index,
                x=escalation_counts.values,
                title="Escalation State Distribution"
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

    # Data table section
    st.markdown("---")
    st.markdown("## 📋 Incident Details")

    # Column selector
    display_columns = st.multiselect(
        "Select columns to display:",
        options=['id', 'name', 'type', 'severity_name', 'status_name', 'affected_country',
                 'impact', 'security_category', 'detection_source', 'hostname', 'created', 'owner'],
        default=['id', 'name', 'severity_name', 'status_name', 'affected_country', 'impact', 'created']
    )

    if display_columns and not filtered_df.empty:
        # Format the dataframe for display
        display_df = filtered_df[display_columns].copy()
        if 'created' in display_df.columns:
            display_df['created'] = display_df['created'].dt.strftime('%Y-%m-%d %H:%M')

        st.dataframe(
            display_df,
            use_container_width=True,
            height=400
        )

        # Export functionality
        col1, col2, col3 = st.columns([1, 1, 4])

        with col1:
            if st.button("📥 Export to CSV"):
                csv = display_df.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"security_incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )

        with col2:
            if st.button("📊 Export Summary"):
                summary_data = {
                    "Total Incidents": len(filtered_df),
                    "Critical Incidents": len(filtered_df[filtered_df['severity'] == 4]),
                    "Open Incidents": len(filtered_df[filtered_df['status'] != 2]),
                    "Countries Affected": filtered_df['affected_country'].nunique(),
                    "Top Country": filtered_df['affected_country'].mode().iloc[0] if not filtered_df.empty else "N/A"
                }
                summary_df = pd.DataFrame(list(summary_data.items()), columns=['Metric', 'Value'])
                csv = summary_df.to_csv(index=False)
                st.download_button(
                    label="Download Summary",
                    data=csv,
                    file_name=f"incident_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666; font-size: 0.8rem;'>
        🛡️ Security Incident Dashboard | Last Updated: {} | Data Source: XSOAR Cache
    </div>
    """.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')), unsafe_allow_html=True)


if __name__ == "__main__":
    main()
