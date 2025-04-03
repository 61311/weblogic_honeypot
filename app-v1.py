import socket
import threading
from flask import Flask, request, render_template_string, Response
import ssl
import os
import json
from datetime import datetime
import datetime 
import requests
import base64
import geoip2.database
import json
import time

# - https://github.com/ZZ-SOCMAP/CVE-2021-35587/blob/main/CVE-2021-35587.py 
# - https://github.com/AymanElSherif/oracle-oam-authentication-bypas-exploit

# Constants
WEBLOGIC_HEADERS = {
    "X-Powered-By": "Servlet/2.5 JSP/2.1",
    "Server": "AdminServer - WebLogic Server 14.1.1.0.0 Thu Mar 26 03:15:09 GMT 2020 2000885 ",
    "Content-Type": "text/html; charset=UTF-8",
    "Location": "http://wls04.oraclecloud.com:7001/console/console.portal",
    "Set-Cookie": "ADMINCONSOLESESSION=XV1CkHPnsKVXIIfvUe9a5pfXDCpkDFm42zBcOtaBhAZbN9In1RA1!-233532985; path=/console/; HttpOnly",
    "X-ORACLE-DMS-ECID": "1a73a826-03da-4903-88e3-ed2b1a6cc0d4-0000021d",
    "X-ORACLE-DMS-RID": "0",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1;mode=block",
    "X-Frame-Options": "SAMEORIGIN"
}

GEOIP_DB_PATH = "GeoLite2-City.mmdb"

# Exploit dictionary
exploit_dict = [
    {
        "exploit": "CVE-2025-21549",
        "exploit_path": "/weblogic/ready",
        "method": "['GET']",
        "response": "Server is ready",
        "response_status": 200,
        "headers": {}
    },
    {
        "exploit": "CVE-2020-14750",
        "exploit_path": "/console/images/%252e%252e%252fconsole.portal",
        "method": "['GET']",
        "response": "Unauthorized access",
        "response_status": 403,
        "headers": {}
    },
    {
        "exploit": "CVE-2020-14882",
        "exploit_path": "/console/css/%252e%252e%252fconsole.portal",
        "method": "['GET']",
        "response": "Unauthorized access",
        "response_status": 403,
        "headers": {}
    },
    {
        "exploit": "CVE-2023-21839",
        "exploit_path": "/_async/AsyncResponseService",
        "method": "['POST']",
        "response": "Internal Server Error",
        "response_status": 500,
        "headers": {}
    },
    {
        "exploit": "CVE-2024-20931",
        "exploit_path": "/console.portal",
        "method": "['GET']",
        "response": "Forbidden",
        "response_status": 403,
        "headers": {}
    }
]

general_exploits = [
    {
        "exploit": "Exploit Attempt",
        "exploit_path": "/wls-wsat/CoordinatorPortType",
        "method": "['POST']",
        "response": "Access denied",
        "response_status": 403,
        "headers": {}
    },
    {
        "exploit": "Exploit Attempt",
        "exploit_path": "/wls-wsat/RegistrationPortTypeRPC",
        "method": "['POST']",
        "response": "Access denied",
        "response_status": 403,
        "headers": {}
    },
    {
        "exploit": "Exploit Attempt",
        "exploit_path": "/bea_wls_internal/",
        "method": "['GET']",
        "response": "Access denied",
        "response_status": 403,
        "headers": {}
    },
    {
        "exploit": "Exploit Attempt",
        "exploit_path": "/uddiexplorer/",
        "method": "['GET']",
        "response": "Access denied",
        "response_status": 403,
        "headers": {}
    },
    {
        "exploit": "Exploit Attempt",
        "exploit_path": "/console/css/login.css",
        "method": "['GET']",
        "response": "Access denied",
        "response_status": 403,
        "headers": {}
    }
]

exploit_dict.extend(general_exploits)

# Random delay to evade fingerprinting  
def random_delay():  
    time.sleep(random.uniform(0.5, 2.5))  

# Helper functions
def weblogic_headers(response):
    date_header = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    WEBLOGIC_HEADERS["Date"] = date_header
    response.headers.update(WEBLOGIC_HEADERS)
    return response

def extract_payload(request):  
    payloads = {}  
    # Get raw request body  
    if request.data:  
        payloads["body"] = request.data.decode(errors="ignore")  
     # Get form data  
    if request.form:  
        payloads["form"] = request.form.to_dict()  
    # Get JSON data  
    try:  
        json_data = request.get_json()  
        if json_data:  
            payloads["json"] = json_data  
    except:  
        pass  
  
    # Get query parameters  
    if request.args:  
        payloads["query"] = request.args.to_dict()  
  
    # Extract encoded payloads (Base64, URL encoding)  
    for key, value in payloads.items():  
        if isinstance(value, str):  
            try:  
                decoded_value = base64.b64decode(value).decode()  
                payloads[f"{key}_decoded"] = decoded_value  
            except:  
                pass  
  
            try:  
                decoded_url = urllib.parse.unquote(value)  
                payloads[f"{key}_url_decoded"] = decoded_url  
            except:  
                pass  

    return payloads  
  
# Save payloads separately for analysis  
def save_payload(ip, data):  
    if data:  
        filename = f"payloads/{ip}_{int(time.time())}.txt"  
        with open(filename, "w") as f:  
            json.dump(data, f, indent=4)  
        logging.info(f"[PAYLOAD SAVED] {filename}")

def get_geoip(ip_address):
    geo_info = {}
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.city(ip_address)
            geo_info = {
                "country": response.country.name,
                "region": response.subdivisions.most_specific.name,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude
            }
    except Exception:
        geo_info = {"country": None, "region": None, "city": None, "latitude": None, "longitude": None}

    isp, asn = "Unknown", "Unknown"
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json").json()
        isp = response.get("org", "Unknown")
    except Exception:
        pass

    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        hostname = "Unknown"
    return {
        "ip": ip_address,
        "hostname": hostname,
        "geo_info": geo_info,
        "isp": isp,
    }

def log_mal_event(event_type, ip, details):
    log_entry = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "event_type": event_type,
        "source_ip": ip,
        "geoip": get_geoip(ip),
        "details": details
    }
    with open("honeypot_mal_events.json", "a") as log_file:
        json.dump(log_entry, log_file)
        log_file.write("\n")
        
def log_gen_event(event_type, ip, details):
    log_entry = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "event_type": event_type,
        "source_ip": ip,
        "geoip": get_geoip(ip),
        "details": details
    }
    with open("honeypo_gen_events.json", "a") as log_file:
        json.dump(log_entry, log_file)
        log_file.write("\n")

# Flask apps
app_8000 = Flask("weblogic_8000")
app_8001 = Flask("weblogic_8001")
app_14100 = Flask("weblogic_14100")
app_14000 = Flask("weblogic_14000")
app_443 = Flask("weblogic_443")
app_14101= Flask("weblogic_14101")

# Processing of Request/Response

def process_input(path):
    for exploit in exploit_dict:
        print(path)
        print(request.data.decode(errors='ignore'))
        if path == exploit["exploit_path"]:
            if request.method in exploit["method"].strip("[]").replace("'", "").split(','):
                # Log the exploit attempt
                ip = request.remote_addr
                data = request.data.decode(errors='ignore')
                user_agent = request.headers.get("User-Agent", "Unknown")
                headers = dict(request.headers)
                payload_data = extract_payload(request)
                save_payload(ip, payload_data) 
                log_mal_event(exploit["exploit"], ip, {"path": request.path, "payload": data, "exploit": exploit["exploit"],"headers": headers,"user_agent": user_agent})
                response_body = exploit["response"]
                response_status = int(exploit.get("response_status", 200))  
                response = Response(response_body, status=response_status)
                weblogic_headers(response)
                random_delay()
                return response
        else:
                ip = request.remote_addr
                data = request.data.decode(errors='ignore')
                user_agent = request.headers.get("User-Agent", "Unknown")
                headers = dict(request.headers)
                payload_data = extract_payload(request)
                save_payload(ip, payload_data) 
                log_gen_event(exploit["exploit"], ip, {"path": request.path, "payload": data, "exploit": exploit["exploit"],"headers": headers,"user_agent": user_agent})
                response_body = exploit["response"]
                response_status = int(exploit.get("response_status", 200))  
                response = Response(response_body, status=response_status)
                weblogic_headers(response)
                random_delay()
                return response
    return Response("Not found", status=404)

# Routes

@app_8000.route("/",defaults={'path': ''}, methods=["GET", "POST"])
def catch_all(path):
    return process_input(path)
@app_8001.route("/",defaults={'path': ''}, methods=["GET", "POST"])
def catch_all(path):
    return process_input(path)
@app_14100.route("/",defaults={'path': ''}, methods=["GET", "POST"])
def catch_all(path):
    return process_input(path)
@app_14000.route("/",defaults={'path': ''}, methods=["GET", "POST"])
def catch_all(path):
    return process_input(path)
@app_443.route("/", defaults={'path': ''},methods=["GET", "POST"])
def catch_all(path):
    return process_input(path)
@app_14101.route("/",defaults={'path': ''}, methods=["GET", "POST"])
def catch_all(path):
    return process_input(path)


# @login_required("/", methods=["GET", "POST"])
# def login():
#     random_delay()  
#     if request.method == "POST":
#         ip = request.remote_addr
#         details = {
#             "username": request.form.get("j_username"),
#             "password": request.form.get("j_password")
#         }
#         log_event("login_attempt", ip, details)
#     return render_template_string(login_page)


# Run Flask apps
def run_flask_app(app, port, use_ssl=False):
    if use_ssl:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
        app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False, ssl_context=context)
    else:
        app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

def t3_handshake_sim(port=7001):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", port))
        server_socket.listen(5)
        print(f"[*] T3 honeypot listening on port {port}")

        while True:
            client_socket, addr = server_socket.accept()
            ip = addr[0]
            print(f"[+] Connection from {addr}")

            try:
                data = client_socket.recv(1024)
                if b"\xac\xed\x00\x05" in data:
                    log_event("serialized_object", ip, {"raw": data.hex()})

                decoded = data.decode(errors='ignore')
                print(f"[>] Received: {decoded.strip()}")

                if decoded.startswith("t3"):
                    response = "HELO:12.2.1\nAS:2048\nHL:19\n\n"
                    client_socket.sendall(response.encode())
                    print("[<] Sent T3 handshake response")
                else:
                    log_event("unexpected_data", ip, {"raw": decoded.strip()})

                payload = client_socket.recv(4096)
                if payload:
                    log_event("t3_payload", ip, {"raw": payload.decode(errors='ignore')})

            except Exception as e:
                print(f"[!] Error: {e}")
            finally:
                client_socket.close()
                print("[*] Connection closed")

if __name__ == "__main__":
    threading.Thread(target=run_flask_app, args=(app_8000, 8000)).start()
    threading.Thread(target=run_flask_app, args=(app_8001, 8001)).start()
    threading.Thread(target=run_flask_app, args=(app_14100, 14100)).start()
    threading.Thread(target=run_flask_app, args=(app_14000, 14000)).start()
    threading.Thread(target=run_flask_app, args=(app_443, 443, True)).start()
    t3_handshake_sim(port=7001)