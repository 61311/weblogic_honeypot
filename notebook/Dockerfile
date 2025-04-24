# Use the Marimo base image with SQL support
FROM ghcr.io/marimo-team/marimo:latest-sql

# Set working directory
WORKDIR /app

# Copy the current directory contents into the container
COPY . /app

# Install additional Python packages for querying and visualization
RUN pip install --no-cache-dir requests pandas plotly

# Expose default Marimo port
EXPOSE 8888

# Start Marimo
CMD ["marimo", "edit", "--no-token", "-p", "8888", "--host", "0.0.0.0"]