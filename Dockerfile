# LLM Security Evaluation Framework
# Reproducible environment for AI Security CLI evaluation

FROM python:3.11-slim

LABEL maintainer="AI Security CLI Team"
LABEL description="Evaluation framework for AI Security CLI"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js for promptfoo
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /eval

# Copy requirements first for caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install promptfoo globally
RUN npm install -g promptfoo

# Copy evaluation framework
COPY . .

# Create results directories
RUN mkdir -p \
    results/aisec \
    results/promptfoo \
    results/garak \
    results/semgrep \
    results/bandit \
    results/secrets \
    results/pip_audit \
    results/scorecard \
    metadata

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Default: show help
CMD ["make", "help"]
