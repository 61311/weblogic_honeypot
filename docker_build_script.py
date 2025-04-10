import os
import subprocess
import shutil
from datetime import datetime
import hashlib

# --- Configuration ---
GIT_REPO_PATH = "/home/opc/honeypot/weblogic_honeypot"
DOCKER_BUILD_DIR = "/home/opc/honeypot/weblogic_honeypot/docker_folder"
TARGET_FILE = "app-v1.py"
CONTAINER_BASE_NAME = "weblogic-honeypot"

def file_hash(filepath):
    """Return SHA256 hash of file contents."""
    if not os.path.exists(filepath):
        return None
    with open(filepath, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def main():
    os.chdir(GIT_REPO_PATH)

    # Pull latest code
    subprocess.run(["git", "pull"], check=True)

    # Check if app-v1.py has changed
    src_file = os.path.join(GIT_REPO_PATH, TARGET_FILE)
    dst_file = os.path.join(DOCKER_BUILD_DIR, TARGET_FILE)

    old_hash = file_hash(dst_file)
    new_hash = file_hash(src_file)

    if old_hash == new_hash:
        print("No changes detected in app-v1.py.")
        return

    print("Changes detected. Updating Docker container...")

    # Copy updated file to docker_build
    shutil.copy2(src_file, dst_file)

    # Create a new Docker image
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    new_image_tag = f"{CONTAINER_BASE_NAME}:{timestamp}"
    subprocess.run(["docker", "build", "--network=host", "-t", new_image_tag, DOCKER_BUILD_DIR], check=True)

    # Stop and remove existing container if running
    result = subprocess.run(["docker", "ps", "-q", "-f", f"name={CONTAINER_BASE_NAME}"], capture_output=True, text=True)
    container_id = result.stdout.strip()

    if container_id:
        subprocess.run(["docker", "stop", container_id], check=True)
        subprocess.run(["docker", "rm", container_id], check=True)

    # Start new container with specified ports and name
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

    subprocess.run(docker_run_cmd, shell=True, check=True)

    print(f"New container started with image: {new_image_tag}")

if __name__ == "__main__":
    main()
