import streamlit as st
import json
import pandas as pd
from datetime import datetime
from pathlib import Path
import plotly.express as px
import plotly.graph_objects as go

# Page config
st.set_page_config(
    page_title="XSOAR Ticket Dashboard",
    page_icon="🎫",
    layout="wide"
)

@st.cache_data
def load_cached_tickets():
    """Load tickets from the cached JSON file"""
    today_date = datetime.now().strftime('%m-%d-%Y')
    root_directory = Path(__file__).parent
    cache_file = root_directory / "web" / "static" / "charts" / today_date / "past_90_days_tickets.json"

    if not cache_file.exists():
        st.error(f"Cache file not found: {cache_file}")
        return []

    with open(cache_file, 'r') as f:
        tickets = json.load(f)

    return tickets

def parse_ticket_data(tickets):
    """Convert ticket data to pandas DataFrame"""
    data = []
    for ticket in tickets:
        data.append({
            'id': ticket.get('id', ''),
            'modified': ticket.get('modified', ''),
            'created': ticket.get('created', ''),
            'name': ticket.get('name', ''),
            'type': ticket.get('type', ''),
            'severity': ticket.get('severity', 0),
            'status': ticket.get('status', 0),
            'owner': ticket.get('owner', ''),
            'closed': ticket.get('closed', ''),
            'phase': ticket.get('phase', ''),
            'parent': ticket.get('parent', ''),
            'roles_count': len(ticket.get('roles', [])),
        })

    df = pd.DataFrame(data)

    # Convert date columns
    for col in ['modified', 'created', 'closed']:
        df[col] = pd.to_datetime(df[col], errors='coerce')

    return df

def main():
    st.title("🎫 XSOAR Ticket Dashboard")
    st.markdown("Interactive dashboard for analyzing cached XSOAR ticket data")

    # Load data
    with st.spinner("Loading cached ticket data..."):
        tickets = load_cached_tickets()

    if not tickets:
        st.error("No ticket data available")
        return

    df = parse_ticket_data(tickets)

    # Sidebar filters
    st.sidebar.header("Filters")

    # Date range filter
    if 'created' in df.columns and df['created'].notna().any():
        min_date = df['created'].min().date()
        max_date = df['created'].max().date()
        date_range = st.sidebar.date_input(
            "Created Date Range",
            value=(min_date, max_date),
            min_value=min_date,
            max_value=max_date
        )

    # Severity filter
    severities = sorted(df['severity'].unique())
    selected_severities = st.sidebar.multiselect(
        "Severity",
        options=severities,
        default=severities
    )

    # Status filter
    statuses = sorted(df['status'].unique())
    selected_statuses = st.sidebar.multiselect(
        "Status",
        options=statuses,
        default=statuses
    )

    # Apply filters
    filtered_df = df[
        (df['severity'].isin(selected_severities)) &
        (df['status'].isin(selected_statuses))
    ]

    if len(date_range) == 2:
        filtered_df = filtered_df[
            (filtered_df['created'].dt.date >= date_range[0]) &
            (filtered_df['created'].dt.date <= date_range[1])
        ]

    # Main dashboard
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Tickets", len(filtered_df))

    with col2:
        avg_severity = filtered_df['severity'].mean()
        st.metric("Avg Severity", f"{avg_severity:.1f}")

    with col3:
        open_tickets = len(filtered_df[filtered_df['status'] != 2])  # Assuming 2 is closed
        st.metric("Open Tickets", open_tickets)

    with col4:
        unique_owners = filtered_df['owner'].nunique()
        st.metric("Unique Owners", unique_owners)

    # Charts
    st.subheader("📊 Analytics")

    col1, col2 = st.columns(2)

    with col1:
        # Tickets by severity
        severity_counts = filtered_df['severity'].value_counts().sort_index()
        fig = px.bar(
            x=severity_counts.index,
            y=severity_counts.values,
            title="Tickets by Severity",
            labels={'x': 'Severity', 'y': 'Count'}
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        # Tickets by status
        status_counts = filtered_df['status'].value_counts()
        fig = px.pie(
            values=status_counts.values,
            names=status_counts.index,
            title="Tickets by Status"
        )
        st.plotly_chart(fig, use_container_width=True)

    # Timeline chart
    if 'created' in filtered_df.columns and filtered_df['created'].notna().any():
        st.subheader("📈 Ticket Creation Timeline")

        # Group by date
        daily_counts = filtered_df.groupby(filtered_df['created'].dt.date).size()

        fig = px.line(
            x=daily_counts.index,
            y=daily_counts.values,
            title="Daily Ticket Creation",
            labels={'x': 'Date', 'y': 'Tickets Created'}
        )
        st.plotly_chart(fig, use_container_width=True)

    # Data table
    st.subheader("📋 Ticket Data")

    # Select columns to display
    display_columns = st.multiselect(
        "Select columns to display:",
        options=df.columns.tolist(),
        default=['id', 'name', 'type', 'severity', 'status', 'owner', 'created']
    )

    if display_columns:
        st.dataframe(
            filtered_df[display_columns],
            use_container_width=True,
            height=400
        )

    # Export data
    if st.button("📥 Export Filtered Data as CSV"):
        csv = filtered_df.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"xsoar_tickets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

if __name__ == "__main__":
    main()