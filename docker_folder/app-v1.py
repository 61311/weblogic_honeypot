import socket
import threading
from flask import Flask, request, render_template_string, Response, send_from_directory, Request, jsonify
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
import random
import logging
import re
from defusedxml.ElementTree import parse as secure_parse
from defusedxml.ElementTree import ParseError
import xmlschema
import urllib.parse
from ecs_logger import log_event



stop_threads = threading.Event()



os.makedirs("captures", exist_ok=True)
os.makedirs("payloads", exist_ok=True)




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

# Event Types
class EventType:
    GENERAL_EVENT_RECORD = "General Event Record"
    CREDENTIAL_CAPTURE = "credential_capture"
    SERIALIZED_OBJECT = "serialized_object"
    UNEXPECTED_DATA = "unexpected_data"
    T3_PAYLOAD = "t3_payload"

# GeoIP DB - Free Version
GEOIP_DB_PATH = "GeoLite2-City.mmdb"

# Validate Ingest XML is XML
def validate_and_secure_xml(xml_file, xsd_file=None):
    """
    Validate and securely parse an XML file.
    - Checks for well-formedness and XXE protection.
    - Optionally validates against an XSD schema.
    """
    if not is_secure_and_well_formed_xml(xml_file):
        return False

    if xsd_file:
        if not validate_xml_with_xsd(xml_file, xsd_file):
            return False

    return True

# Validate Ingest XML is XML

def is_secure_and_well_formed_xml(xml_file):
    """
    Check if the XML file is well-formed and secure (protected against XXE).
    """
    try:
        secure_parse(xml_file)
        return True
    except ParseError as e:
        return False
    except Exception as e:
        return False
    
def validate_xml_with_xsd(xml_file, xsd_file):
    """
    Validate the XML file against an XSD schema.
    """
    try:
        schema = xmlschema.XMLSchema(xsd_file)
        schema.validate(xml_file)
        return True
    except xmlschema.exceptions.XMLSchemaValidationError as e:
        return False
    except Exception as e:
        return False

# List of CVE and other security related items that will be emulated

exploit_dict = [
    {
        "exploit": "CVE-2025-21549",
        "exploit_path": "/weblogic/ready",
        "method": "['GET']",
        "response": "Server is ready",
        "response_status": 200,
        "headers": {},
        "description": "WebLogic readiness check endpoint."
    },
    {
        "exploit": "CVE-2020-14750",
        "exploit_path": "/console/images/%252e%252e%252fconsole.portal",
        "method": "['GET']",
        "response": "Unauthorized access",
        "response_status": 403,
        "headers": {},
        "description": "Unauthenticated remote code execution via path traversal."
    },
        {
        "exploit": "CVE-2020-14750",
        "exploit_path": "/console/images/%2e%2e%2fconsole.portal",
        "method": "['GET']",
        "response": "Unauthorized access",
        "response_status": 403,
        "headers": {},
        "description": "Unauthenticated remote code execution via path traversal."
    },
    {
        "exploit": "CVE-2020-14882",
        "exploit_path": "/console/css/%252e%252e%252fconsole.portal",
        "method": "['GET']",
        "response": "Unauthorized access",
        "response_status": 403,
        "headers": {},
        "description": "Path traversal vulnerability allowing unauthenticated remote code execution."
    },
    {
        "exploit": "CVE-2023-21839",
        "exploit_path": "/_async/AsyncResponseService",
        "method": "['POST']",
        "response": "Internal Server Error",
        "response_status": 500,
        "headers": {},
        "description": "Remote code execution vulnerability in WebLogic asynchronous service."
    },
    {
        "exploit": "CVE-2024-20931",
        "exploit_path": "/console.portal",
        "method": "['GET']",
        "response": "Forbidden",
        "response_status": 403,
        "headers": {},
        "description": "Access control vulnerability in WebLogic console."
    },
    {
        "exploit": "CVE-2019-2725",
        "exploit_path": "/wls-wsat/CoordinatorPortType",
        "method": "['POST']",
        "response": "Access denied",
        "response_status": 403,
        "headers": {},
        "description": "Deserialization vulnerability allowing remote code execution."
    },
    {
        "exploit": "CVE-2019-2729",
        "exploit_path": "/wls-wsat/RegistrationPortTypeRPC",
        "method": "['POST']",
        "response": "Access denied",
        "response_status": 403,
        "headers": {},
        "description": "Deserialization vulnerability allowing remote code execution."
    },
    {
        "exploit": "CVE-2019-2890",
        "exploit_path": "/bea_wls_internal/",
        "method": "['GET']",
        "response": "Access denied",
        "response_status": 403,
        "headers": {},
        "description": "Remote code execution vulnerability in WebLogic internal endpoints."
    },
    {
        "exploit": "CVE-2018-2894",
        "exploit_path": "/uddiexplorer/",
        "method": "['GET']",
        "response": "WebLogic UDDI Explorer",
        "response_status": 200,
        "headers": {},
        "description": "Directory traversal vulnerability in WebLogic UDDI Explorer."
    },
    {
        "exploit": "CVE-2021-35587",
        "exploit_path": "/oam/server/",
        "method": "['POST']",
        "response": "Access denied",
        "response_status": 403,
        "headers": {},
        "description": "Authentication bypass vulnerability in Oracle Access Manager."
    },
    {
        "exploit": "CVE-2023-21931",
        "exploit_path": "/oamconsole/afr/a/remote/",
        "method": "['GET']",
        "response": "ADF_FACES-30200: Fatal exception during PhaseId: RESTORE_VIEW",
        "response_status": 500,
        "headers": {},
        "description": "Remote code execution vulnerability in Oracle Access Manager."
    },
    {
        "exploit": "CVE-2022-21510",
        "exploit_path": "/oam/server/",
        "method": "['GET']",
        "response": "Access denied",
        "response_status": 403,
        "headers": {},
        "description": "Vulnerability in Oracle Access Manager allowing unauthenticated access to sensitive data."
    },
    {
        "exploit": "CVE-2017-10271",
        "exploit_path": "/wls-wsat/CoordinatorPortType",
        "method": "['POST']",
        "response": "Access denied",
        "response_status": 403,
        "headers": {},
        "description": "XMLDecoder deserialization vulnerability in WebLogic Server."
    },
    {
        "exploit": "CVE-2018-2628",
        "exploit_path": "/wls-wsat/CoordinatorPortType",
        "method": "['POST']",
        "response": "Access denied",
        "response_status": 403,
        "headers": {},
        "description": "Remote code execution vulnerability in WebLogic Server due to unsafe deserialization."
    },
    {
        "exploit": "Exploit Attempt",
        "exploit_path": "/console/css/login.css",
        "method": "['GET']",
        "response": "Access denied",
        "response_status": 403,
        "headers": {}
    },
    {
        "exploit": "CVE-2020-14750",
        "exploit_path": "/OA_HTML/BneOfflineLOVService",
        "method": "['POST']",
        "response": '''<?xml version="1.0" encoding="UTF-8"?><bne:document xmlns:bne="http://www.oracle.com/bne"><bne:messages xmlns:bne="http://www.oracle.com/bne"><bne:message bne:type="ERROR" bne:text="Cannot be logged in as GUEST." bne:cause="" bne:action="" /></bne:messages></bne:document>''',
        "response_status": 200,
        "headers": {},
        "description": "Oracle E-Business Suite vulnerability allowing unauthorized access."
    },
        {
        "exploit": "CVE-2021-35587",
        "exploit_path": "/oamconsole/afr/a/remote/",
        "method": "['GET']",
        "response": "ADF_FACES-30200:For more information, please see the server&#39;s error log for an entry beginning with: The UIViewRoot is null. Fatal exception during PhaseId: RESTORE_VIEW 1.",
        "response_status": 500,
        "headers": {},
        "description": "Authentication bypass vulnerability in Oracle Access Manager."
        },
    {
        "exploit": "CVE-2020-2586",
        "exploit_path": "/OA_HTML/BneApplicationService",
        "method": "['POST']",
        "response": "Access denied",
        "response_status": 403,
        "headers": {},
        "description": "Unauthenticated access to sensitive data in Oracle E-Business Suite."
    },
    {
        "exploit": "CVE-2020-2587",
        "exploit_path": "/OA_HTML/BneWebService",
        "method": "['POST']",
        "response": "Internal Server Error",
        "response_status": 500,
        "headers": {},
        "description": "Remote code execution vulnerability in Oracle E-Business Suite."
    },
    {
        "exploit": "CVE-2019-2638",
        "exploit_path": "/OA_HTML/BneUploaderService",
        "method": "['POST']",
        "response": "Access denied",
        "response_status": 403,
        "headers": {},
        "description": "Unauthenticated access to sensitive data in Oracle E-Business Suite."
    },
    {
        "exploit": "CVE-2018-2893",
        "exploit_path": "/OA_HTML/BneOfflineLOVService",
        "method": "['POST']",
        "response": '''<?xml version="1.0" encoding="UTF-8"?><bne:document xmlns:bne="http://www.oracle.com/bne"><bne:messages xmlns:bne="http://www.oracle.com/bne"><bne:message bne:type="ERROR" bne:text="Cannot be logged in as GUEST." bne:cause="" bne:action="" /></bne:messages></bne:document>''',
        "response_status": 200,
        "headers": {},
        "description": "Directory traversal vulnerability in Oracle E-Business Suite."
    },
    {
        "exploit": "CVE-2021-2295",
        "exploit_path": "/OA_HTML/BneDataService",
        "method": "['POST']",
        "response": "Access denied",
        "response_status": 403,
        "headers": {},
        "description": "SQL injection vulnerability in Oracle E-Business Suite."
    },
        {
        "exploit": "JSPSpy Webshell",
        "exploit_path": "/x.jsp",
        "method": "['GET', 'POST']",
        "response": "JSPSpy Webshell is ready.",
        "response_status": 200,
        "headers": {},
        "description": "Emulated JSPSpy webshell endpoint."
    },
    {
        "exploit": "China Chopper Webshell",
        "exploit_path": "/aa.jsp",
        "method": "['POST']",
        "response": "Success",
        "response_status": 200,
        "headers": {},
        "description": "Emulated China Chopper webshell endpoint."
    },
        {
        "exploit": "A.txt In Root Path",
        "exploit_path": "/a.txt",
        "method": "['GET']",
        "response": "Success",
        "response_status": 200,
        "headers": {},
        "description": "Emulated Compromised Host with Attacker File."
    },
    {
        "exploit": "CVE-2021-35587",
        "exploit_path": "/oam/server/opensso/sessionservice",
        "method": "['POST']",
        "response": (
            "<html>\n"
            "<head><title>oracle access manager</title></head>\n"
            "<body>\n"
            "<link rel=\"stylesheet\" type=\"text/css\" href=\"/oam/pages/css/login_page.css\">\n"
            "</body>\n"
            "</html>"
        ),
        "response_status": 200,
        "headers": {
            "Set-Cookie": "x-oracle-dms-ecid=12345; Path=/; HttpOnly",
            "Set-Cookie": "x-oracle-dms-rid=67890; Path=/; HttpOnly"
        },
        "description": "Authentication bypass vulnerability in Oracle Access Manager."
    }
]


# Random delay to evade fingerprinting  
def random_delay():  
    time.sleep(random.uniform(0.5, 2.5))  

# Helper functions
def weblogic_headers(response):
    date_header = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    WEBLOGIC_HEADERS["Date"] = date_header
    response.headers.update(WEBLOGIC_HEADERS)
    return response

# Function to download XXE file from remote locations - for single vuln only 
    
def download_remote_xml_from_payload(payload_str):
    """
    Download and validate XML files from a remote URL.
    """
    match = re.search(r'ClassPathXmlApplicationContext\(\s*(https?://[^)\\]+)\s*\)', payload_str)
    if match:
        url = match.group(1)
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            os.makedirs("captures", exist_ok=True)
            filename = f"captures/xml_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xml"
            with open(filename, 'wb') as f:
                f.write(response.content)

            xsd_file = "schema.xsd"  # Replace with your actual schema file path
            if not validate_and_secure_xml(filename, xsd_file):
                pass
            else:
                pass
        except requests.exceptions.RequestException as e:
            pass
        except Exception as e:
            pass

# For POST extract payloads 

def extract_payload(request):
    """
    Extract payloads from an HTTP request, including raw body, form data, JSON, and query parameters.
    Handles Base64 and URL-encoded payloads.
    """
    payloads = {}

    # Extract raw request body
    if request.data:
        try:
            payloads["body"] = request.data.decode(errors="ignore")
        except Exception as e:
            pass

    # Extract form data
    if request.form:
        try:
            form_data = request.form.to_dict()
            payloads["form"] = form_data

            # Handle specific keys in form data (e.g., 'handle')
            if 'handle' in form_data:
                handle_payload = form_data['handle']
                download_remote_xml_from_payload(handle_payload)
        except Exception as e:
            pass

    # Extract JSON data
    try:
        json_data = request.get_json()
        if json_data:
            payloads["json"] = json_data
    except Exception as e:
        pass

    # Extract query parameters
    if request.args:
        try:
            payloads["query"] = request.args.to_dict()
        except Exception as e:
            pass

    # Decode Base64 and URL-encoded payloads
    for key, value in payloads.items():
        if isinstance(value, str):
            # Attempt Base64 decoding
            try:
                decoded_value = base64.b64decode(value).decode(errors="ignore")
                payloads[f"{key}_base64_decoded"] = decoded_value
            except Exception:
                pass  # Ignore errors for non-Base64 strings

            # Attempt URL decoding
            try:
                decoded_url = urllib.parse.unquote(value)
                payloads[f"{key}_url_decoded"] = decoded_url
            except Exception:
                pass  # Ignore errors for non-URL-encoded strings

    return payloads

# Save payloads separately for analysis  
def save_payload(ip, data):  
    if data:  
        filename = f"payloads/{ip}_{int(time.time())}.txt"  
        with open(filename, "w") as f:  
            json.dump(data, f, indent=4)  

# Look up Locations 
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

def log_gen_event(event_type, ip, details):
    geo_data = get_geoip(ip) or {}
    geo_info = geo_data.get("geo_info", {})

    data = {
        "source_ip": ip,
        "city_name": geo_info.get("city"),
        "region_name": geo_info.get("region"),
        "country_name": geo_info.get("country"),
        "latitude": geo_info.get("latitude"),
        "longitude": geo_info.get("longitude"),
        "hostname": geo_data.get("hostname"),
        "isp": geo_data.get("isp"),
        "extra": {
            "details": details
        }
    }

    log_event(
        event_type=event_type,
        category="network",
        data=data
    )
# Log General Connection to none exploitable paths 

def log_mal_event(event_type, ip, details):
    geo_data = get_geoip(ip) or {}
    geo_info = geo_data.get("geo_info", {})

    data = {
        "source_ip": ip,
        "city_name": geo_info.get("city"),
        "region_name": geo_info.get("region"),
        "country_name": geo_info.get("country"),
        "latitude": geo_info.get("latitude"),
        "longitude": geo_info.get("longitude"),
        "hostname": geo_data.get("hostname"),
        "isp": geo_data.get("isp"),
        "extra": {
            "details": details
        }
    }

    log_event(
        event_type=event_type,
        category="intrusion_detection",
        data=data
    )


# Processing of Request/Response
def process_input(path: str, request: Request) -> Response:
    """Process an incoming request and check for potential exploits."""

    def handle_exploit(exploit: dict) -> Response:
        """Handle a detected exploit."""
        ip = request.remote_addr
        request_data = request.data.decode(errors='ignore')
        user_agent = request.headers.get("User-Agent", "Unknown")
        headers = dict(request.headers)
        payload_data = extract_payload(request)

        log_mal_event(exploit["exploit"], ip, {
            "path": request.path,
            "payload": request_data,
            "exploit": exploit["exploit"],
            "headers": headers,
            "user_agent": user_agent
        })

        print(f"[DEBUG] Exploit detected: {exploit['exploit']} from IP: {ip}")

        save_payload(ip, payload_data)

        response_body = exploit["response"]
        response_status = int(exploit.get("response_status", 200))
        response = Response(response_body, status=response_status)
        weblogic_headers(response)
        random_delay()
        return response

    for exploit in exploit_dict:
        if request.path == exploit["exploit_path"]:
            return handle_exploit(exploit)

    # If no exploit is matched, log a general event and serve the index.html file
    try:
        ip = request.remote_addr
        user_agent = request.headers.get("User-Agent", "Unknown")
        headers = dict(request.headers)
        payload_data = extract_payload(request)
        log_gen_event("General Event Record", ip, {
            "path": request.path,
            "payload": payload_data,
            "headers": headers,
            "user_agent": user_agent
        })
        save_payload(ip, payload_data)
        directory_path = 'source/oam/pages'
        if not os.path.exists(directory_path):
            return Response("Internal Server Error: Directory not found", status=500)
        return send_from_directory(directory_path, 'login.html')
    except Exception as e:
        print(f"[ERROR] Exception in process_input: {e}")
        return Response("Internal Server Error", status=500)

# Routes
def serve_index():
    return send_from_directory('source/oam/pages', 'login.html')

# Flask app initialization
apps = {
    8080: Flask("weblogic_8080"),
    8000: Flask("weblogic_8000"),
    8001: Flask("weblogic_8001"),
    14100: Flask("weblogic_14100"),
    14000: Flask("weblogic_14000"),
    8443: Flask("weblogic_8443"),
    14101: Flask("weblogic_14101")
}

# Load API key from environment variable (default to a placeholder if not set)
API_KEY = os.getenv("API_KEY", "your_secret_api_key")

# Load IP allowlist from environment variable (comma-separated values)
IP_ALLOWLIST = os.getenv("IP_ALLOWLIST", "").split(",")

# Unified route for all apps
for port, app in apps.items():
    @app.after_request
    def apply_weblogic_headers(response):
        """Ensure WebLogic headers are applied to all HTTP responses."""
        weblogic_headers(response)
        return response

    @app.route('/log', methods=['POST'])
    def log_credentials():
        try:
            data = request.get_json()
            if not data or 'username' not in data or 'password' not in data:
                return jsonify({'status': 'error', 'message': 'Invalid request data'}), 400

            ip = request.remote_addr
            geo_data = get_geoip(ip) or {}
            geo_info = geo_data.get("geo_info", {})
            username = data['username']
            password = data['password']
            details = {
                "username": username,
                "password": password,
                "headers": dict(request.headers),
                "user_agent": request.headers.get("User-Agent", "Unknown")
            }
            ecs_data = {
                "source_ip": ip,
                "city_name": geo_info.get("city"),
                "region_name": geo_info.get("region"),
                "country_name": geo_info.get("country"),
                "latitude": geo_info.get("latitude"),
                "longitude": geo_info.get("longitude"),
                "hostname": geo_data.get("hostname"),
                "isp": geo_data.get("isp"),
                "extra": {
                    "details": details
                }
            }


            log_event(
                event_type="credentials_captured",
                category="intrusion_detection",
                data=ecs_data
            )

            return jsonify({'status': 'success'}), 200

        except Exception as e:
            return jsonify({'status': 'error', 'message': 'Internal error'}), 500
    @app.route('/honeypot/auth', methods=['POST'])
    def honeypot_auth():
        return "Login failed. Invalid credentials.", 403
    @app.route('/images/<path:filename>')
    def serve_image(filename):
        return send_from_directory('source/oam/pages/images', filename)
    @app.route('/css/<path:filename>')
    def serve_css(filename):
        return send_from_directory('source/oam/pages/css', filename)
    @app.route('/js/<path:filename>')
    def serve_js(filename):
        return send_from_directory('source/oam/pages/js', filename)
    @app.route('/a.txt', methods=['GET'])
    def serve_a_txt():
        """
        Emulate a response for a.txt.
        """
        ip = request.remote_addr
        user_agent = request.headers.get("User-Agent", "Unknown")

        # Log the interaction
        log_gen_event("a.txt Access", ip, {
            "user_agent": user_agent,
            "path": "/a.txt"
        })

        # Define the content of the text file
        response_content = """# This is a simulated response for a.txt
    # Timestamp: {}
    # IP Address: {}
    # User-Agent: {}
    """.format(datetime.datetime.now(datetime.timezone.utc).isoformat(), ip, user_agent)
    # Return the response
        return Response(response_content, status=200, mimetype='text/plain')
    @app.route('/console/j_security_check', methods=['POST'])
    def weblogic_weak_login():
        username = request.form.get('j_username', '')
        password = request.form.get('j_password', '')
        ip = request.remote_addr

        # Log the login attempt
        log_mal_event("weblogic_weak_login_attempt", ip, {
            "username": username,
            "password": password,
            "headers": dict(request.headers),
            "user_agent": request.headers.get("User-Agent", "Unknown")
        })

        # Simulate a weak login response
        if username == "weblogic" and password == "weblogic":
            response = Response("<html><body>Login successful</body></html>", status=200)
        else:
            response = Response("<html><body>Login failed</body></html>", status=403)

        weblogic_headers(response)
        return response
    @app.route('/api/logs', methods=['GET'])
    def get_logs():
        """API endpoint to fetch logs with optional filters."""
        # Check for API key in headers
        api_key = request.headers.get('X-API-Key')
        if api_key != API_KEY:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401

        # Check if the client's IP is in the allowlist
        # client_ip = request.remote_addr
        # if client_ip not in IP_ALLOWLIST:
        #     return jsonify({"status": "error", "message": "IP not allowed"}), 401

        event_type = request.args.get('event_type')
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')

        logs = []
        log_file_path = "/app/logs/honeypot_events.log"

        try:
            with open(log_file_path, 'r') as log_file:
                for line in log_file:
                    log_entry = json.loads(line)

                    # Apply filters
                    if event_type and log_entry.get('event_data', {}).get('event_subtype') != event_type:
                        continue
                    if start_time and log_entry['@timestamp'] < start_time:
                        continue
                    if end_time and log_entry['@timestamp'] > end_time:
                        continue

                    logs.append(log_entry)

            return jsonify({"status": "success", "logs": logs}), 200

        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
    @app.route("/", defaults={'path': ''}, methods=["GET", "POST"])
    @app.route("/<path:path>", methods=["GET", "POST"])
    def catch_all(path):
        if path == "" or path == "/":
            return serve_index()
        return process_input(path, request)





# Run Flask apps
def run_flask_app(app, port, use_ssl=False):
    if use_ssl:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
        app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False, ssl_context=context)
    else:
        app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

def log_t3_event(event_type, ip, port, extra=None):
    geo = get_geoip(ip) or {}
    geo_info = geo.get("geo_info", {})

    data = {
        "source_ip": ip,
        "port": port,
        "user_agent": None,
        "url_path": None,
        "city_name": geo_info.get("city"),
        "region_name": geo_info.get("region"),
        "country_name": geo_info.get("country"),
        "latitude": geo_info.get("latitude"),
        "longitude": geo_info.get("longitude"),
        "isp": geo_info.get("isp"),
        "exploit": None,
        "headers": {},
        "payload": extra.get("payload") if extra else None,
        "ascii": extra.get("ascii") if extra else None,
        "hex": extra.get("hex_dump") if extra else None,
        "extra": extra or {}
    }

    log_event(
        event_type=event_type,
        category="network",
        data=data
    )

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org").text.strip()
    except Exception:
        return "127.0.0.1"

def save_raw_t3(ip, raw_data):
    os.makedirs("captures/t3", exist_ok=True)
    filename = f"captures/t3/{ip}_{int(time.time())}.bin"
    with open(filename, "wb") as f:
        f.write(raw_data)

def save_serialized_stream(ip, data):
    marker = b"\xac\xed\x00\x05"
    if marker in data:
        start = data.find(marker)
        stream = data[start:]
        os.makedirs("captures/t3", exist_ok=True)
        filename = f"captures/t3/serialized_{ip}_{int(time.time())}.ser"
        with open(filename, "wb") as f:
            f.write(stream)

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org").text.strip()
    except Exception:
        return "127.0.0.1"

def save_raw_t3(ip, raw_data):
    os.makedirs("captures/t3", exist_ok=True)
    filename = f"captures/t3/{ip}_{int(time.time())}.bin"
    with open(filename, "wb") as f:
        f.write(raw_data)

def save_serialized_stream(ip, data):
    marker = b"\xac\xed\x00\x05"
    if marker in data:
        start = data.find(marker)
        stream = data[start:]
        os.makedirs("captures/t3", exist_ok=True)
        filename = f"captures/t3/serialized_{ip}_{int(time.time())}.ser"
        with open(filename, "wb") as f:
            f.write(stream)

def t3_handshake_sim(port=7001):
    PUBLIC_IP = get_public_ip()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", port))
        server_socket.listen(5)

        while not stop_threads.is_set():
            try:
                client_socket, addr = server_socket.accept()
                ip = addr[0]
                
                log_t3_event("t3 protocol - connection", ip, port)

                try:
                    data = client_socket.recv(1024)
                    if not data:
                        continue

                    decoded = data.decode(errors="ignore").strip()
                    log_t3_event("t3 protocol - received_raw", ip, port, {
                        "hex_dump": data.hex(),
                        "ascii": decoded
                    })

                    save_raw_t3(ip, data)
                    save_serialized_stream(ip, data)

                    # HTTP redirect case
                    if any(decoded.upper().lstrip().startswith(m) for m in ["GET", "POST", "HEAD", "HTTP", "OPTIONS", "PUT", "CONNECT"]):
                        log_t3_event("t3 protocol - http_probe_detected", ip, port, {
                            "ascii": decoded
                        })

                        redirect_response = (
                            f"HTTP/1.1 302 Found\r\n"
                            f"Location: https://{PUBLIC_IP}:8443/\r\n"
                            f"Content-Length: 0\r\n"
                            f"Connection: close\r\n\r\n"
                        )

                        try:
                            client_socket.sendall(redirect_response.encode())
                            log_t3_event("t3 protocol - sent_redirect", ip, port)
                            time.sleep(0.5)
                            client_socket.shutdown(socket.SHUT_WR)
                            client_socket.close()
                            log_t3_event("t3 protocol - closed_after_redirect", ip, port)
                            continue
                        except Exception as e:
                            log_t3_event("t3 protocol - send_redirect_failed", ip, port, {"error": str(e)})
                            client_socket.close()
                            continue

                    # Java serialization detection
                    if b"\xac\xed\x00\x05" in data:
                        log_t3_event("t3 protocol - java_serialized_marker", ip, port)

                        fake_error = (
                            b"Exception: java.lang.ClassNotFoundException: ysoserial.payloads.CommonsCollections1\n"
                            b"at weblogic.rjvm.MsgAbbrevInputStream.readObject(MsgAbbrevInputStream.java:528)\n"
                        )

                        try:
                            client_socket.sendall(fake_error)
                            log_t3_event("t3 protocol - sent_deserialization_error", ip, port)
                            time.sleep(0.5)
                            client_socket.shutdown(socket.SHUT_WR)
                            client_socket.close()
                            log_t3_event("t3 protocol - closed_after_fake_error", ip, port)
                            continue
                        except Exception as e:
                            log_t3_event("t3 protocol - send_error_failed", ip, port, {"error": str(e)})
                            client_socket.close()
                            continue

                    # T3 handshake simulation
                    if decoded.startswith("t3"):
                        version = random.choice(["12.2.1.4.0", "14.1.1.0", "12.1.3.0"])
                        asn = random.randint(1024, 32767)
                        hl = random.randint(10, 50)
                        ms = random.randint(500, 5000)

                        response = f"HELO:{version}\nAS:{asn}\nHL:{hl}\nMS:{ms}\n\n"
                        client_socket.sendall(response.encode())

                        log_t3_event("t3 protocol - sent_helo", ip, port, {
                            "version": version,
                            "asn": asn,
                            "hl": hl,
                            "ms": ms
                        })

                    else:
                        log_t3_event("t3 protocol - not_a_t3_handshake", ip, port)

                    # Optional secondary payload
                    try:
                        payload = client_socket.recv(4096)
                        if payload:
                            log_t3_event("t3 protocol - secondary_payload", ip, port, {
                                "hex_dump": payload.hex(),
                                "ascii": payload.decode(errors="ignore")
                            })
                            save_raw_t3(ip, payload)
                            save_serialized_stream(ip, payload)
                    except socket.timeout:
                        pass

                    # Hold session if not closed early
                    time.sleep(random.randint(10, 30))

                except Exception as e:
                    log_t3_event("t3 protocol - error", ip, port, {"error": str(e)})
                finally:
                    client_socket.close()
                    log_t3_event("t3 protocol - disconnection", ip, port)

            except socket.error:
                break


    
def main():
    """
    Main function to start the honeypot services.
    """
    PUBLIC_IP = get_public_ip()

    try:
        # Start Flask apps on different ports
        for port, app in apps.items():
            use_ssl = port == 8443  # Enable SSL only for port 8443
            threading.Thread(target=run_flask_app, args=(app, port, use_ssl), daemon=True).start()

        # Start T3 protocol simulation
        t3_thread = threading.Thread(target=t3_handshake_sim, args=(7001,), daemon=True)
        t3_thread.start()

        # Keep the main thread alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        stop_threads.set()

if __name__ == "__main__":
    main()