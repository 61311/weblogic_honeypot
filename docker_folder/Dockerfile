# Update Python version to 3.10 to ensure compatibility with Flask and Werkzeug
FROM python:3.10-slim-bullseye

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Python app and dependencies
COPY app-v1.py /app/
COPY ecs_logger.py /app/
COPY requirements.txt /app/
COPY source /app/source
COPY cert.pem /app/
COPY key.pem /app/
COPY GeoLite2-City.mmdb /app/

# Install required Python packages
RUN pip install --no-cache-dir -r requirements.txt


# Copy Filebeat config and entrypoint
COPY entrypoint.sh /entrypoint.sh


# Set permissions
RUN chmod +x /entrypoint.sh && chmod 777 /app/logs

# Expose honeypot ports
EXPOSE 8080 8000 8001 14100 14000 8443 14101 7001

# Start the app and Filebeat
ENTRYPOINT ["/entrypoint.sh"]
