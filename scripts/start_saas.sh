#!/bin/bash
set -e

echo "🚀 Starting ComplianceBot SaaS MVP..."

# 1. Install Dependencies
echo "Installing Python dependencies..."
python3 -m pip install -r requirements.txt || echo "Warning: pip install failed. Ensure venv is active."

# 2. Start Infra (Redis + Postgres)
echo "Starting Database & Queue (Clean Slate)..."
docker-compose down -v # Ensure fresh DB init
docker-compose up -d
echo "Waiting for DB to initialize (10s)..."
sleep 10

# 3. Create DB Tables
echo "Initializing Database..."
python3 -c "from compliancebot.saas.db.base import Base, engine; from compliancebot.saas.db import models; Base.metadata.create_all(bind=engine)"

# 4. Start Services in Background
echo "Starting Worker (RQ)..."
# Using nohup to keep it running
nohup rq worker --url redis://localhost:6379/0 compliancebot.saas.worker.tasks > worker.log 2>&1 &
WORKER_PID=$!
echo "Worker started (PID $WORKER_PID). Logs: worker.log"

echo "Starting API (FastAPI)..."
nohup uvicorn compliancebot.saas.api.main:app --reload --port 8000 > api.log 2>&1 &
API_PID=$!
echo "API started (PID $API_PID). Logs: api.log"

echo "✅ SaaS is LIVE!"
echo "---------------------------------------------------"
echo "API: http://localhost:8000"
echo "Webhook: http://localhost:8000/webhook (Forwarded by Smee)"
echo "Worker: Background process"
echo "---------------------------------------------------"
echo "To stop: kill $WORKER_PID $API_PID && docker-compose down"
