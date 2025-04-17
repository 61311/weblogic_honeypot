import socket
import time

HONEYPOT_IP = "129.146.76.211"
T3_PORT = 7001
BUFFER_SIZE = 4096

def test_t3_handshake():
    print("[*] Testing T3 handshake...")

    with socket.create_connection((HONEYPOT_IP, T3_PORT), timeout=5) as s:
        s.sendall(b"t3 12.2.1\nAS:256\nHL:19\n\n")
        response = s.recv(BUFFER_SIZE).decode(errors="ignore")
        print("→ Response:\n", response)
        assert "HELO" in response, "T3 HELO response not received"
        print("[+] T3 handshake test passed.")

def test_serialized_payload():
    print("[*] Testing serialized Java object payload...")

    # Basic Java stream header with a dummy object string
    payload = b"\xac\xed\x00\x05t\x00\x10TestSerializedObject\n"

    with socket.create_connection((HONEYPOT_IP, T3_PORT), timeout=5) as s:
        s.settimeout(3)
        s.sendall(payload)

        # Read loop with timeout safety
        data = b""
        try:
            while True:
                chunk = s.recv(BUFFER_SIZE)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass

        response = data.decode(errors="ignore")
        print("→ Response:\n", response)
        assert "ClassNotFoundException" in response, "Fake deserialization error not returned"
        print("[+] Serialized payload test passed.")

def test_http_probe_redirect():
    print("[*] Testing HTTP probe (GET request)...")

    with socket.create_connection((HONEYPOT_IP, T3_PORT), timeout=5) as s:
        s.settimeout(3)
        s.sendall(b"GET / HTTP/1.1\r\nHost: honeypot.local\r\nUser-Agent: curl\r\n\r\n")

        response_data = b""
        try:
            while True:
                chunk = s.recv(BUFFER_SIZE)
                if not chunk:
                    break
                response_data += chunk
        except socket.timeout:
            pass

        response = response_data.decode(errors="ignore")
        print("→ Response:\n", response)

        assert "302 Found" in response, "Redirect response not received"
        assert "Location:" in response, "Missing Location header in response"
        print("[+] HTTP probe redirect test passed.")

def main():
    test_t3_handshake()
    time.sleep(1)

    test_http_probe_redirect()
    print("\n[✓] All T3 simulation tests passed.")

    test_serialized_payload()
    time.sleep(1)



if __name__ == "__main__":
    main()
