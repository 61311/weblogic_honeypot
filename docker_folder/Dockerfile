# Update Python version to 3.10 to ensure compatibility with Flask and Werkzeug
FROM python:3.10-slim-bullseye

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set environment variable for Filebeat version
ENV FILEBEAT_VERSION=8.13.4

# Create necessary directories
RUN mkdir -p /app /app/logs /opt/filebeat

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

# Install Filebeat
RUN curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-${FILEBEAT_VERSION}-linux-x86_64.tar.gz && \
    tar xzvf filebeat-${FILEBEAT_VERSION}-linux-x86_64.tar.gz && \
    mv filebeat-${FILEBEAT_VERSION}-linux-x86_64/* /opt/filebeat/ && \
    rm -rf filebeat-${FILEBEAT_VERSION}-linux-x86_64*

# Copy Filebeat config and entrypoint
COPY filebeat.yml /opt/filebeat/filebeat.yml
COPY entrypoint.sh /entrypoint.sh

# Set correct permissions for Filebeat configuration
RUN chmod go-w /opt/filebeat/filebeat.yml

# Set permissions
RUN chmod +x /entrypoint.sh && chmod 777 /app/logs

# Expose honeypot ports
EXPOSE 8080 8000 8001 14100 14000 8443 14101 7001

# Start the app and Filebeat
ENTRYPOINT ["/entrypoint.sh"]
