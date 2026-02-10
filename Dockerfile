FROM python:3.11-slim

# Install nmap
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy and install requirements
COPY prototype/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy prototype app code
COPY prototype/ .

# Railway sets PORT env var
ENV PORT=5000
EXPOSE 5000

# Run with gunicorn for production
CMD gunicorn --bind 0.0.0.0:$PORT --workers 2 --timeout 120 app:app
