import os
import subprocess
import shutil
from datetime import datetime
import hashlib
import argparse
import time

# --- Configuration ---
GIT_REPO_PATH = "/home/opc/honeypot/docker_folder"
DOCKER_BUILD_DIR = "/home/opc/honeypot/docker_folder"
TARGET_FILE = "app-v1.py"
CONTAINER_BASE_NAME = "weblogic_honeypot"

def file_hash(filepath):
    """Return SHA256 hash of file contents."""
    if not os.path.exists(filepath):
        return None
    with open(filepath, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def stop_and_remove_existing_container(container_name):
    """Stop and remove an existing container if it is running or stopped."""
    try:
# Check for running container
        result = subprocess.run(["docker", "ps", "-q", "-f", f"name={container_name}"], capture_output=True, text=True)
        container_id = result.stdout.strip()

        if container_id:
            print(f"Stopping and removing running container: {container_name}")
            subprocess.run(["docker", "stop", container_id], check=True)
            subprocess.run(["docker", "rm", container_id], check=True)

        # Check for stopped container
        result = subprocess.run(["docker", "ps", "-a", "-q", "-f", f"name={container_name}"], capture_output=True, text=True)
        container_id = result.stdout.strip()

        if container_id:
            print(f"Removing stopped container: {container_name}")
            subprocess.run(["docker", "rm", container_id], check=True)

    except subprocess.CalledProcessError as e:
        print(f"Error stopping/removing container: {e}")

def main():
    parser = argparse.ArgumentParser(description="Docker build script for WebLogic honeypot.")
    parser.add_argument("--force", action="store_true", help="Force container rebuild even if app-v1.py has not changed.")
    args = parser.parse_args()

    os.chdir(GIT_REPO_PATH)

    # Pull latest code
    subprocess.run(["git", "pull"], check=True)

    # Create a new Docker image with build date/time in the name
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    new_image_tag = f"{CONTAINER_BASE_NAME}:{timestamp}"
    subprocess.run(["docker", "build", "--network=host", "-t", new_image_tag, DOCKER_BUILD_DIR], check=True)

    # Stop and remove existing container if running
    stop_and_remove_existing_container(CONTAINER_BASE_NAME)

    # Define the docker_run_cmd variable before using it
    docker_run_cmd = f"""
    docker run -d \
    -p 8080:8080 \
    -p 8000:8000 \
    -p 8001:8001 \
    -p 14100:14100 \
    -p 14000:14000 \
    -p 8443:8443 \
    -p 14101:14101 \
    -p 7001:7001 \
    --name {CONTAINER_BASE_NAME} \
    {new_image_tag}
    """

    try:
        result = subprocess.run(docker_run_cmd, shell=True, capture_output=True, text=True, check=True)
        print(f"New container started with image: {new_image_tag}")
        print(f"Docker run output: {result.stdout}")
        print("Waiting for docker container to start...")
        time.sleep(10)  # Wait for the container to start
        print("Testing Honeypot is Running Successfully...")
        subprocess.run(["python3","test_app_v1.py"], check=True)
        print("Test completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error starting container: {e.stderr}")
        print("Please check the Docker logs for more details.")
        

if __name__ == "__main__":
    main()
