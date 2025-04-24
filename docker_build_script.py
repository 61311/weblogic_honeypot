import os
import subprocess
import shutil
from datetime import datetime
import hashlib
import argparse
import time
import secrets
import ipaddress

# --- Configuration ---
GIT_REPO_PATH = "/home/opc/honeypot/docker_folder"
DOCKER_BUILD_DIR = "/home/opc/honeypot/docker_folder"
OPERATING_FOLDER = "/home/opc/honeypot/"
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

def backup_container_data(container_name, backup_dir):
    """Backup the captures/ and payloads/ folders from the container to the host."""
    try:
        os.makedirs(backup_dir, exist_ok=True)  # Create the directory if it doesn't exist
        captures_backup_path = os.path.join(backup_dir, "captures")
        payloads_backup_path = os.path.join(backup_dir, "payloads")

        print(f"Backing up captures/ folder from container {container_name}...")
        subprocess.run(["docker", "cp", f"{container_name}:/app/captures", captures_backup_path], check=True)

        print(f"Backing up payloads/ folder from container {container_name}...")
        subprocess.run(["docker", "cp", f"{container_name}:/app/payloads", payloads_backup_path], check=True)

        print(f"Backup completed. Data saved to {backup_dir}")
    except subprocess.CalledProcessError as e:
        print(f"Error during backup: {e}")

def generate_api_key():
    """Generate a secure API key."""
    return secrets.token_urlsafe(32)

def is_valid_subnet(subnet):
    """Validate if a given string is a valid subnet."""
    try:
        ipaddress.ip_network(subnet, strict=False)
        return True
    except ValueError:
        return False

def build_and_run_marimo_container():
    """Build and run the Marimo container for querying the honeypot API."""
    MARIMO_CONTAINER_NAME = "marimo_instance"
    MARIMO_IMAGE_NAME = "marimo_image"
    MARIMO_PORT = 8888

    # Build the Marimo container
    print("Building the Marimo container...")
    subprocess.run([
        "docker", "build", "-t", MARIMO_IMAGE_NAME, "./notebook"
    ], check=True)

    # Stop and remove any existing Marimo container
    try:
        subprocess.run([
            "docker", "rm", "-f", MARIMO_CONTAINER_NAME
        ], check=True)
    except subprocess.CalledProcessError:
        print("No existing Marimo container to remove.")

    # Run the Marimo container
    print("Starting the Marimo container...")
    subprocess.run([
        "docker", "run", "-d",
        "--name", MARIMO_CONTAINER_NAME,
        "-p", f"{MARIMO_PORT}:{MARIMO_PORT}",
        MARIMO_IMAGE_NAME
    ], check=True)

    # Print connection information
    print(f"Marimo container is running.")
    print(f"Access the Marimo interface at: http://localhost:{MARIMO_PORT}")

def main():
    parser = argparse.ArgumentParser(description="Docker build script for WebLogic honeypot.")
    # Set default backup directory to a folder with the current date in the local directory
    default_backup_dir = os.path.join(os.getcwd(), datetime.now().strftime("%Y-%m-%d"))
    parser.add_argument("--backup-dir", default=default_backup_dir, help="Directory to save container backups.")
    parser.add_argument("--force", action="store_true", help="Force container rebuild even if app-v1.py has not changed.")
    parser.add_argument("--skip-test", action="store_true", help="Skip running the test script after container deployment.")
    args = parser.parse_args()

    os.chdir(GIT_REPO_PATH)

    # Pull latest code
    subprocess.run(["git", "pull"], check=True)

    # Backup container data before stopping it
    backup_container_data(CONTAINER_BASE_NAME, args.backup_dir)

    # Generate a secure API key
    api_key = generate_api_key()
    print(f"Generated API Key: {api_key}")

    # Define the IP allowlist (subnet-based)
    ip_allowlist = "10.0.0.0/8"
    if not is_valid_subnet(ip_allowlist):
        raise ValueError(f"Invalid subnet: {ip_allowlist}")

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
    --dns=8.8.8.8 \
    --dns=8.8.4.4 \
    -e API_KEY={api_key} \
    -e IP_ALLOWLIST={ip_allowlist} \
    --name {CONTAINER_BASE_NAME} \
    {new_image_tag}
    """

    try:
        result = subprocess.run(docker_run_cmd, shell=True, capture_output=True, text=True, check=True)
        print(f"New container started with image: {new_image_tag}")
        print(f"Docker run output: {result.stdout}")
        print("Waiting for docker container to start...")
        time.sleep(10)  # Wait for the container to start

        if not args.skip_test:
            print("Testing Honeypot is Running Successfully...")
            try:
                original_cwd = os.getcwd()
                test_script_path = os.path.join(OPERATING_FOLDER, "test_app_v1.py")
                if os.path.exists(test_script_path):
                    subprocess.run(["python3", test_script_path], check=True)
                else:
                    print(f"Test script not found at {test_script_path}. Skipping test.")
                try:
                    subprocess.run(["python3", "test_app_v1.py"], check=True)
                finally:
                    os.chdir(original_cwd)
                print("Test completed successfully.")
            except subprocess.CalledProcessError as e:
                print(f"Error during test execution: {e.stderr}")
                print("Please check the test script logs for more details.")
    except subprocess.CalledProcessError as e:
        print(f"Error starting container: {e.stderr}")
        print("Please check the Docker logs for more details.")

    # Build and run the Marimo container
    build_and_run_marimo_container()

if __name__ == "__main__":
    main()
