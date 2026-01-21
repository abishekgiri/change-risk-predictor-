# Use official Python runtime as a parent image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies (e.g., for SQLite if needed, git for cloning if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose the port (Streamlit uses 8501, Uvicorn uses 8000)
# We might need to choose one entrypoint or use a supervisor if running both.
# For production, we usually run the API server (Uvicorn).
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run the FastApi server by default
CMD ["uvicorn", "riskbot.server:app", "--host", "0.0.0.0", "--port", "8000"]
