# Use an official Python runtime as a parent image
FROM python:3.9-slim

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
COPY {name of GeoIP DB} 

# Install required Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Expose the ports used by the honeypot
EXPOSE 8080 8000 8001 14100 14000 8443 14101 7001

# Command to run the application
CMD ["python", "app-v1.py"]
