import streamlit as st
import sqlite3
import pandas as pd
import json
import os
import sys

# Add project root to path so we can import riskbot modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from riskbot.config import RISK_DB_PATH
from riskbot.storage.sqlite import add_label
from riskbot.model.train import train as train_model

st.set_page_config(page_title="RiskBot Ops", page_icon="🛡️", layout="wide")

# --- Helper Functions ---
def get_db_connection():
    return sqlite3.connect(RISK_DB_PATH)

def load_data():
    conn = get_db_connection()
    # Load all runs
    query = """
    SELECT repo, pr_number, risk_score, risk_level, created_at, reasons_json, features_json
    FROM pr_runs
    ORDER BY created_at DESC
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    # Process JSON columns
    df['reasons'] = df['reasons_json'].apply(lambda x: json.loads(x) if x else [])
    df['reason_summary'] = df['reasons'].apply(lambda x: "; ".join(x) if x else "")
    # Fix: use mixed format to handle variations in SQLite timestamps
    df['created_at'] = pd.to_datetime(df['created_at'], format='mixed')
    return df

def load_stats():
    conn = get_db_connection()
    total = conn.execute("SELECT COUNT(*) FROM pr_runs").fetchone()[0]
    high_risk = conn.execute("SELECT COUNT(*) FROM pr_runs WHERE risk_level='HIGH'").fetchone()[0]
    labeled = conn.execute("SELECT COUNT(*) FROM pr_labels").fetchone()[0]
    conn.close()
    return total, high_risk, labeled

def load_unlabeled_prs():
    conn = get_db_connection()
    # Find runs that are NOT in pr_labels
    query = """
    SELECT r.repo, r.pr_number, r.risk_score, r.risk_level, r.created_at
    FROM pr_runs r
    LEFT JOIN pr_labels l ON r.repo = l.repo AND r.pr_number = l.pr_number
    WHERE l.id IS NULL
    ORDER BY r.created_at DESC
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

# --- Sidebar Filters ---
st.sidebar.title("🛡️ Controls")
df = load_data()

repos = ["All"] + list(df['repo'].unique()) if not df.empty else ["All"]
selected_repo = st.sidebar.selectbox("Filter by Repository", repos)

if selected_repo != "All":
    df = df[df['repo'] == selected_repo]

# --- Main Dashboard ---
st.title("🛡️ RiskBot Control Panel")

# 1. KPI Cards
total_prs = len(df)
high_risk_prs = len(df[df['risk_level'] == 'HIGH'])
avg_score = df['risk_score'].mean() if not df.empty else 0

kpi1, kpi2, kpi3, kpi4 = st.columns(4)
kpi1.metric("Total Analyzed", total_prs)
kpi2.metric("High Risk", high_risk_prs, delta_color="inverse")
kpi3.metric("Avg Risk Score", f"{avg_score:.1f}")

# train Readiness
_, _, labeled_count = load_stats()
ml_target = 5  # Lowered from 50 for testing/demo purposes
progress = min(labeled_count / ml_target, 1.0)
kpi4.metric("Labeled Data (ML Ready)", f"{labeled_count} / {ml_target}")
if labeled_count < ml_target:
    kpi4.progress(progress)
else:
    kpi4.success("Ready for Training!")

# 2. Charts
st.divider()

col_charts1, col_charts2 = st.columns(2)

with col_charts1:
    st.subheader("Risk Level Distribution")
    if not df.empty:
        risk_counts = df['risk_level'].value_counts()
        st.bar_chart(risk_counts, color="#ff4b4b")
    else:
        st.info("No data yet.")

with col_charts2:
    st.subheader("Risk Score Trend")
    if not df.empty:
        ts_df = df.set_index('created_at').sort_index()
        st.line_chart(ts_df['risk_score'], color="#00ff00")
    else:
        st.info("No data yet.")

# 3. Labeling Interface
st.divider()
st.subheader("🏷️ Labeling Queue")

unlabeled_df = load_unlabeled_prs()
if selected_repo != "All":
    unlabeled_df = unlabeled_df[unlabeled_df['repo'] == selected_repo]

if unlabeled_df.empty:
    st.success("🎉 All caught up! No unlabeled PRs.")
else:
    # Create display string
    unlabeled_df['display'] = unlabeled_df.apply(
        lambda x: f"{x['repo']} #{x['pr_number']} (Risk: {x['risk_score']})", axis=1
    )
    
    col_label_sel, col_label_act = st.columns([2, 2])
    
    with col_label_sel:
        target_pr_str = st.selectbox("Select PR to Label", unlabeled_df['display'])
    
    if target_pr_str:
        row = unlabeled_df[unlabeled_df['display'] == target_pr_str].iloc[0]
        repo_val = row['repo']
        pr_val = int(row['pr_number'])
        
        with col_label_act:
            st.write(f"**Action for {repo_val} #{pr_val}**")
            b1, b2, b3, b4 = st.columns(4)
            if b1.button("✅ Safe"):
                add_label(repo_val, pr_val, "safe", 0)
                st.rerun()
            if b2.button("⚠️ Hotfix"):
                add_label(repo_val, pr_val, "hotfix", 1)
                st.rerun()
            if b3.button("⏪ Rollback"):
                add_label(repo_val, pr_val, "rollback", 4)
                st.rerun()
            if b4.button("🔥 Incident"):
                add_label(repo_val, pr_val, "incident", 5)
                st.rerun()

# 4. Detailed History Table
st.divider()
st.subheader("📜 Analysis History")

display_cols = ['created_at', 'repo', 'pr_number', 'risk_level', 'risk_score', 'reason_summary']

if not df.empty:
    st.dataframe(
        df[display_cols].style.applymap(
            lambda v: 'color: red; font-weight: bold;' if v == 'HIGH' else ('color: orange;' if v == 'MEDIUM' else 'color: green;'),
            subset=['risk_level']
        ), 
        use_container_width=True,
        column_config={
            "created_at": st.column_config.DatetimeColumn("Analyzed At", format="D MMM, HH:mm"),
            "repository": "Repo",
            "risk_score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%d"),
            "reason_summary": "Reasons"
        }
    )
else:
    st.info("No analysis runs recorded yet.")

# 5. ML Training (Sidebar)
st.sidebar.divider()
st.sidebar.subheader("🤖 ML Operations")
if labeled_count >= ml_target:
    if st.sidebar.button("Train Model Now"):
        with st.sidebar.status("Training model..."):
            try:
                train_model()
                st.sidebar.success("Training Complete!")
            except Exception as e:
                st.sidebar.error(f"Failed: {e}")
else:
    st.sidebar.warning(f"Need {ml_target - labeled_count} more labels to train.")
