import socket
import time

HONEYPOT_IP = "129.146.76.211"  # Replace if needed
T3_PORT = 7001
BUFFER_SIZE = 4096

def recv_until_close(sock, timeout=5):
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(BUFFER_SIZE)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        print("[!] Timeout reached while waiting for server response")
    return data

def test_t3_handshake():
    print("[*] Testing T3 handshake...")

    with socket.create_connection((HONEYPOT_IP, T3_PORT), timeout=10) as s:
        s.sendall(b"t3 12.2.1\nAS:256\nHL:19\n\n")
        response = recv_until_close(s).decode(errors="ignore")

    print("→ Response:\n", response)
    assert "HELO" in response, "T3 HELO response not received"
    print("[+] T3 handshake test passed.\n")

def test_serialized_payload():
    print("[*] Testing serialized Java object payload...")

    payload = b"\xac\xed\x00\x05t\x00\x10TestSerializedObject\n"

    with socket.create_connection((HONEYPOT_IP, T3_PORT), timeout=10) as s:
        s.sendall(payload)
        time.sleep(1.0)
        s.shutdown(socket.SHUT_WR)

        response_data = recv_until_close(s)
        response = response_data.decode(errors="ignore")
        print("→ Raw response from honeypot:\n", repr(response))

    cleaned = response.replace("\r", "").replace("\n", "").lower()

    if "classnotfoundexception" not in cleaned:
        print("[!] Fake deserialization error not detected in response.")
        print("[!] Full response for analysis:\n", cleaned)

    assert "classnotfoundexception" in cleaned, "Fake deserialization error not returned"
    print("[+] Serialized payload test passed.\n")

def test_http_probe_redirect():
    print("[*] Testing HTTP probe (GET request)...")

    request = b"GET / HTTP/1.1\r\nHost: honeypot\r\nUser-Agent: test-client\r\n\r\n"

    with socket.create_connection((HONEYPOT_IP, T3_PORT), timeout=10) as s:
        s.sendall(request)
        time.sleep(1.0)
        s.shutdown(socket.SHUT_WR)

        response_data = recv_until_close(s)
        response = response_data.decode(errors="ignore")
        print("→ Raw response from honeypot:\n", repr(response))

    if "302 Found" not in response:
        print("[!] 302 redirect not found in response — did the honeypot actually send it?")
        print("[!] Response headers received:")
        print(response)

    assert "302 Found" in response, "Redirect response not received"
    assert "Location:" in response, "Location header missing in redirect"
    print("[+] HTTP probe redirect test passed.\n")

def main():
    test_t3_handshake()
    #test_serialized_payload()
    test_http_probe_redirect()
    print("[✓] All tests completed successfully.")

if __name__ == "__main__":
    main()
