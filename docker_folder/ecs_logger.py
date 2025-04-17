import logging
import json
import os
from datetime import datetime

log_dir = "/app/logs"
os.makedirs(log_dir, exist_ok=True)
log_path = os.path.join(log_dir, "honeypot_events.log")

logger = logging.getLogger("honeypot")
logger.setLevel(logging.INFO)
handler = logging.FileHandler(log_path)
handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(handler)

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

def log_event(event_type, category, data):
    geo = get_geoip(data.get("source_ip", "")) or {}

    ecs_event = {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "event": {
            "kind": "event",
            "category": [category],
            "type": ["alert"] if category == "intrusion_detection" else ["info"]
        },
        "source": {
            "ip": data.get("source_ip"),
            "geo": {
                "city_name": geo.get("city"),
                "country_name": geo.get("country"),
                "region_name": geo.get("region"),
                "location": {
                    "lat": geo.get("latitude"),
                    "lon": geo.get("longitude")
                }
            }
        },
        "user_agent": {
            "original": data.get("user_agent")
        },
        "url": {
            "path": data.get("url_path")
        },
        "event_data": {
            "event_type": event_type,
            "exploit": data.get("exploit"),
            "headers": data.get("headers", {}),
            "payload": data.get("payload"),
            "hex": data.get("hex"),
            "ascii": data.get("ascii"),
            "port": data.get("port"),
            "extra": data.get("extra", {})
        }
    }

    logger.info(json.dumps(ecs_event))