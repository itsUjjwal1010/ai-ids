# Use Python 3.11 slim — compatible with all packages (pandas, xgboost, scikit-learn)
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies needed for some Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (Docker layer caching — only reinstalls if requirements change)
COPY requirements.txt .

# --prefer-binary: use pre-built wheels instead of compiling from source
# This cuts build time from 25+ minutes to ~2 minutes
RUN pip install --no-cache-dir --prefer-binary -r requirements.txt

# Copy the rest of the application
COPY . .

# Render injects PORT at runtime
EXPOSE 5000

# Run with gunicorn — production WSGI server
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--timeout", "120", "ids_inference_server:app"]
