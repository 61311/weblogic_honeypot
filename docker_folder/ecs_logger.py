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


def log_event(event_type, category, data):

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
                "city_name": data.get("city_name"),
                "country_name": data.get("country_name"),
                "region_name": data.get("region_name"),
                "location": {
                    "lat": data.get("latitude"),
                    "lon": data.get("longitude")
                }
            },
            "as" : {
                "organization": {
                    "name": data.get("isp")
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
            "event_subtype": event_type,  # Renamed from 'event_type'
            "exploit": data.get("exploit"),
            "headers": data.get("headers", {}),
            "payload": data.get("payload"),
            "hex": data.get("hex"),
            "ascii": data.get("ascii"),
            "port": data.get("port"),
            "extra": data.get("extra", {})
        },
        "host": {
            "name": data.get("hostname", "unknown")
        }
    }

    logger.info(json.dumps(ecs_event))