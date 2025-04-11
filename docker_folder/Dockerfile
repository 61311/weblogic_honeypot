# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Set environment
ENV FILEBEAT_VERSION=8.13.4

# Set the working directory in the container
WORKDIR /app

# Copy the application code into the container
COPY app-v1.py /app/
COPY requirements.txt /app/

# Copy the source directory
COPY source /app/source

# Create and set permissions for the logs directory
RUN mkdir /app/logs && chmod 777 /app/logs

# Copy SSL certificates
COPY cert.pem /app/
COPY key.pem /app/

#Copy GEOIP DB
COPY GeoLite2-City.mmdb /app/

# Install required Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Create app directories
RUN mkdir -p /opt/filebeat /var/log/supervisor

RUN curl -L -O https://urldefense.com/v3/__https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-$*7BFILEBEAT_VERSION*7D-linux-x86_64.tar.gz__;JSU!!ACWV5N9M2RV99hQ!I-5JkFxBPziDvIxWs9_Wv0s3end4_C_WEy8YPmcdwqxCvIPPmNdmNokxs9LeBHptOBuur-72AeXVQ2TL6w$  && \
    tar xzvf filebeat-${FILEBEAT_VERSION}-linux-x86_64.tar.gz && \
    mv filebeat-${FILEBEAT_VERSION}-linux-x86_64/* /opt/filebeat/ && \
    rm -rf filebeat-${FILEBEAT_VERSION}-linux-x86_64*


# Copy Filebeat configuration
COPY filebeat.yml /opt/filebeat/filebeat.yml

# Supervisor configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf


# Expose the ports used by the honeypot
EXPOSE 8080 8000 8001 14100 14000 8443 14101 7001

# Command to run the application
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
