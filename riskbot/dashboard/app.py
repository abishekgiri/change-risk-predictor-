import streamlit as st
import sqlite3
import pandas as pd
import os
import sys

# Add project root to path so we can import riskbot modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from riskbot.config import RISK_DB_PATH
from riskbot.storage.sqlite import add_label
from riskbot.model.train import train as train_model

st.set_page_config(page_title="RiskBot Ops", page_icon="🛡️", layout="wide")

st.title("🛡️ RiskBot Control Panel")

# --- Helper Functions ---
def get_db_connection():
    return sqlite3.connect(RISK_DB_PATH)

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
    LIMIT 20
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def load_recent_runs():
    conn = get_db_connection()
    query = """
    SELECT repo, pr_number, risk_score, risk_level, created_at, features_json
    FROM pr_runs
    ORDER BY created_at DESC
    LIMIT 10
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

# --- 1. Stats & Readiness ---
total, high_risk, labeled = load_stats()
ml_target = 50

col1, col2, col3 = st.columns(3)
col1.metric("Total PRs Analyzed", total)
col2.metric("High Risk PRs", high_risk)
col3.metric("Labeled Data", f"{labeled} / {ml_target}")

st.write("### ML Readiness")
progress = min(labeled / ml_target, 1.0)
st.progress(progress)

if labeled < ml_target:
    st.info(f"🧠 **Training Disabled**: Need {ml_target - labeled} more labeled PRs to build a reliable model.")
else:
    st.success("🧠 **ML Ready**: You have enough data to train the model.")

# --- 2. Training Control ---
st.divider()
st.subheader("⚙️ Model Training")

col_train, col_status = st.columns([1, 4])

with col_train:
    if labeled >= ml_target:
        if st.button("🚀 Train Model", type="primary"):
            with st.spinner("Training model..."):
                try:
                    train_model()
                    st.success("Model trained and saved to `data/model.pkl`!")
                except Exception as e:
                    st.error(f"Training failed: {e}")
    else:
        st.button("🚀 Train Model", disabled=True, help="Need 50 labeled PRs")

# --- 3. Labeling Interface ---
st.divider()
st.subheader("🏷️ Labeling Queue (Unlabeled PRs)")

unlabeled_df = load_unlabeled_prs()

if unlabeled_df.empty:
    st.info("No unlabeled PRs found! Good job clearing the queue.")
else:
    # Create a nice label for the selectbox
    unlabeled_df['display'] = unlabeled_df.apply(
        lambda x: f"{x['repo']} #{x['pr_number']} (Score: {x['risk_score']}) - {x['created_at']}", axis=1
    )
    
    selected_pr_str = st.selectbox("Select a PR to label:", unlabeled_df['display'])
    
    # Extract selected PR details
    if selected_pr_str:
        selected_row = unlabeled_df[unlabeled_df['display'] == selected_pr_str].iloc[0]
        repo = selected_row['repo']
        pr_num = int(selected_row['pr_number'])
        
        st.write(f"**Selected:** `{repo} #{pr_num}`")
        
        l_col1, l_col2, l_col3, l_col4 = st.columns(4)
        
        if l_col1.button("✅ Safe"):
            add_label(repo, pr_num, "safe", severity=0)
            st.rerun() # Refresh to remove from list
            
        if l_col2.button("⚠️ Hotfix"):
            add_label(repo, pr_num, "hotfix", severity=1)
            st.rerun()
            
        if l_col3.button("🔥 Incident"):
            add_label(repo, pr_num, "incident", severity=5)
            st.rerun()
            
        if l_col4.button("⏪ Rollback"):
            add_label(repo, pr_num, "rollback", severity=4)
            st.rerun()

# --- 4. Recent Activity ---
st.divider()
st.subheader("Recent Activity")
st.dataframe(load_recent_runs(), use_container_width=True)
