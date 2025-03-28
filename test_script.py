import requests

# --- Test T3 handshake (port 7001) ---
def test_t3_handshake(host='129.146.76.211', port=7001):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, port))
            handshake = b"t3 12.2.1\nAS:2048\nHL:19\n\n"
            sock.sendall(handshake)
            response = sock.recv(1024)
            print("[T3] Response:", response.decode(errors='ignore').strip())
    except Exception as e:
        print("[T3] FAILED:", e)

# --- Test HTTP(S) endpoints ---
def test_http_ports(host='129.146.76.211'):
    ports = [8000, 8001, 14100, 14000]
    for port in ports:
        try:
            resp = requests.get(f"http://{host}:{port}/")
            print(f"[HTTP {port}] OK:", resp.status_code)
        except Exception as e:
            print(f"[HTTP {port}] FAILED:", e)

# --- Test HTTPS endpoint (port 443) ---
def test_https(host='129.146.76.211'):
    try:
        resp = requests.get(f"https://{host}:443/", verify=False, timeout=5)
        print(f"[HTTPS 443] OK:", resp.status_code)
    except Exception as e:
        print(f"[HTTPS 443] FAILED:", e)

# --- Test exploit endpoint with dummy payload ---
def test_exploit_post(host='129.146.76.211', port=8000):
    path = "/wls-wsat/CoordinatorPortType"
    payload = b"<soap>EXPLOIT</soap>"
    try:
        resp = requests.post(f"http://{host}:{port}{path}", data=payload)
        print(f"[Exploit POST {port}] OK:", resp.status_code)
    except Exception as e:
        print(f"[Exploit POST {port}] FAILED:", e)

if __name__ == "__main__":
    print("""\n=== Honeypot Validation Script ===\n""")
    test_t3_handshake()
    test_http_ports()
    test_https()
    test_exploit_post()
