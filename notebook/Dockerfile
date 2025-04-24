# Use a lightweight Python base image
FROM python:3.10-slim-bullseye

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Marimo and required Python packages
RUN pip install --no-cache-dir marimo requests pandas plotly

# Expose default Marimo port
EXPOSE 8888

# Start Marimo
CMD ["marimo", "--ip", "0.0.0.0", "--port", "8888"]