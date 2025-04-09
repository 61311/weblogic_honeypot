import requests
import socket
import json
import time

BASE_URLS = [
    "http://127.0.0.1:8000",
    "https://127.0.0.1:8080"
    "http://127.0.0.1:8001",
    "http://127.0.0.1:14100",
    "http://127.0.0.1:14000",
    "http://127.0.0.1:14101",
    "https://127.0.0.1:8443"
]

EXPLOIT_PATHS = [
    "/weblogic/ready",
    "/console/images/%252e%252e%252fconsole.portal",
    "/console/css/%252e%252e%252fconsole.portal",
    "/_async/AsyncResponseService",
    "/console.portal",
    "/wls-wsat/CoordinatorPortType",
    "/wls-wsat/RegistrationPortTypeRPC",
    "/bea_wls_internal/",
    "/uddiexplorer/",
    "/console/css/login.css"
]

def test_exploit_paths():
    for base_url in BASE_URLS:
        for path in EXPLOIT_PATHS:
            try:
                url = f"{base_url}{path}"
                response = requests.get(url, timeout=5)
                print(f"GET {url} -> Status: {response.status_code}, Response: {response.text[:100]}")
            except Exception as e:
                print(f"Error testing {url}: {e}")

def test_login(base_url):
    try:
        url = f"{base_url}/log"
        payload = {"username": "test_user", "password": "test_pass"}
        response = requests.post(url, json=payload, timeout=5)
        print(f"POST {url} -> Status: {response.status_code}, Response: {response.json()}")
    except Exception as e:
        print(f"Error testing login at {base_url}: {e}")

def test_t3_emulator():
    try:
        with socket.create_connection(("127.0.0.1", 7001), timeout=5) as sock:
            sock.sendall(b"t3 12.2.1\n")
            response = sock.recv(1024)
            print(f"T3 Emulator Response: {response.decode(errors='ignore')}")
    except Exception as e:
        print(f"Error connecting to T3 emulator: {e}")

if __name__ == "__main__":
    print("Testing exploit paths...")
    test_exploit_paths()
    
    print("\nTesting login functionality...")
    for base_url in BASE_URLS:
        test_login(base_url)
    
    print("\nTesting T3 emulator...")
    test_t3_emulator()
