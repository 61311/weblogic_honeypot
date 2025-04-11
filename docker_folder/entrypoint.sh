#!/bin/bash
set -e

# Start Filebeat in the background
/opt/filebeat/filebeat -e -c /opt/filebeat/filebeat.yml &

# Start your honeypot (adjust if filename is different)
python /app/app-v1.py