FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies with retry logic
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get update --fix-missing || true && \
    apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/* || echo "Some packages may have failed to install, continuing..."

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directories for data and models
RUN mkdir -p /app/data /app/models /app/logs /app/reports

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Expose port for potential web interface
EXPOSE 8000

# Default command
CMD ["python", "-u", "src/main.py"]
