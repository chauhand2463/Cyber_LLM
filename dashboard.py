import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import os

# Page Config
st.set_page_config(
    page_title="CyberLLM Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CSS Styling ---
st.markdown("""
<style>
    .reportview-container {
        background: #0e1117;
    }
    .main {
        background: #0e1117;
    }
    h1, h2, h3 {
        color: #00ff41 !important; /* Hacker Green */
        font-family: 'Courier New', Courier, monospace;
    }
    .stMetric {
        background-color: #1f2937;
        border: 1px solid #374151;
        padding: 10px;
        border-radius: 5px;
    }
    .stDataFrame {
        border: 1px solid #374151;
    }
</style>
""", unsafe_allow_html=True)

# --- Database Connection ---
DB_PATH = "llm_working_folder/memory.db"

def load_data(table_name):
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query(f"SELECT * FROM {table_name}", conn)
    except:
        df = pd.DataFrame() # Table might not exist yet
    conn.close()
    return df

# --- Sidebar ---
st.sidebar.title("🛡️ CyberLLM Agents")
st.sidebar.markdown("---")
page = st.sidebar.radio("Navigation", ["Overview", "Live Incidents", "Knowledge Base", "System Stats"])

# --- Overview Page ---
if page == "Overview":
    st.title("🛡️ Security Operations Center")
    st.markdown("Welcome to the **CyberLLM Agentic Platform**. Real-time monitoring active.")
    
    col1, col2, col3 = st.columns(3)
    
    events_df = load_data("threat_events")
    kb_df = load_data("knowledge_base")
    
    total_incidents = len(events_df)
    total_kb = len(kb_df) if not kb_df.empty else 0
    avg_risk = events_df['risk_score'].mean() if not events_df.empty else 0
    
    col1.metric("Total Incidents Scanned", total_incidents)
    col2.metric("Known Threats Learned", total_kb)
    col3.metric("Average Risk Score", f"{avg_risk:.1f}")
    
    if not events_df.empty:
        st.subheader("Recent Activity")
        # Format timestamp
        if 'timestamp' in events_df.columns:
            events_df['timestamp'] = pd.to_datetime(events_df['timestamp'])
            events_df = events_df.sort_values('timestamp', ascending=False)
        
        st.dataframe(events_df[['timestamp', 'scenario_name', 'risk_score', 'event_details']].head(10), use_container_width=True)
    else:
        st.info("No incident data found yet. Run a scenario!")

# --- Live Incidents Page ---
elif page == "Live Incidents":
    st.title("🚨 Live Incident Feed")
    
    events_df = load_data("threat_events")
    if not events_df.empty:
        # Filter by Risk
        risk_filter = st.slider("Filter by Risk Score", 0, 100, (0, 100))
        filtered_df = events_df[(events_df['risk_score'] >= risk_filter[0]) & (events_df['risk_score'] <= risk_filter[1])]
        
        st.dataframe(filtered_df, use_container_width=True)
        
        # Detail View
        if not filtered_df.empty:
            selected_id = st.selectbox("Select Incident to Inspect", filtered_df['id'][:20])
            incident = filtered_df[filtered_df['id'] == selected_id].iloc[0]
            
            st.markdown("### Incident Details")
            st.json(incident['event_details'])
    else:
        st.warning("No incidents to display.")

# --- Knowledge Base Page ---
elif page == "Knowledge Base":
    st.title("🧠 AI Knowledge Base")
    st.markdown("Patterns learned by the AI from past investigations.")
    
    kb_df = load_data("knowledge_base")
    if not kb_df.empty:
        for index, row in kb_df.iterrows():
            with st.expander(f"{row['timestamp']} - {row['incident_id']} ({row['verdict']})"):
                st.markdown(f"**Pattern Summary:** {row['pattern_summary']}")
                st.markdown(f"**Action Taken:** {row['action_taken']}")
    else:
        st.info("Knowledge Base is empty. Agents learn from high-confidence incidents.")

# --- System Stats Page ---
elif page == "System Stats":
    st.title("📊 System Analytics")
    
    events_df = load_data("threat_events")
    if not events_df.empty:
        col1, col2 = st.columns(2)
        
        # Risk Distribution
        fig_risk = px.histogram(events_df, x="risk_score", nbins=20, title="Risk Score Distribution", color_discrete_sequence=['#00ff41'])
        col1.plotly_chart(fig_risk, use_container_width=True)
        
        # Scenarios Count
        fig_scenarios = px.pie(events_df, names="scenario_name", title="Scenarios Executed", hole=0.4)
        col2.plotly_chart(fig_scenarios, use_container_width=True)
        
        # Timeline
        if 'timestamp' in events_df.columns:
            events_df['timestamp'] = pd.to_datetime(events_df['timestamp'])
            events_df = events_df.sort_values('timestamp')
            fig_time = px.line(events_df, x="timestamp", y="risk_score", title="Risk Trend Over Time", markers=True)
            st.plotly_chart(fig_time, use_container_width=True)
    else:
        st.markdown("Not enough data for analytics.")
