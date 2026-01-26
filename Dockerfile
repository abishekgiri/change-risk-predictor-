# Base image: Official Python 3.10 Slim (Clean, small, Debian-based)
FROM python:3.10-slim

# Prevent Python from writing pyc files to disc
ENV PYTHONDONTWRITEBYTECODE=1
# Prevent Python from buffering stdout and stderr
ENV PYTHONUNBUFFERED=1

# Create a non-root user (UID 1000) named 'compliancebot'
RUN groupadd -g 1000 compliancebot && \
    useradd -m -u 1000 -g compliancebot compliancebot

# Set working directory to /app for installation
WORKDIR /app

# Upgrade pip
RUN pip install --upgrade pip

# Copy dependency definitions first (caching layer)
COPY requirements.txt pyproject.toml /app/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY compliancebot /app/compliancebot
COPY README.md LICENSE /app/

# Install the package
RUN pip install --no-cache-dir .

# Create workspace directory for volume mounts
WORKDIR /workspace

# Switch to non-root user
USER compliancebot

# Define entrypoint
ENTRYPOINT ["compliancebot"]

# Default command
CMD ["--help"]
