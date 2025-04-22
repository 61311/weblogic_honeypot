import logging
import json
from datetime import datetime

class ECSFormatter(logging.Formatter):
    def format(self, record):
        # Ensure the log record is serialized as a clean JSON object
        log_record = {
            "@timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "log.level": record.levelname.lower(),
            "message": json.loads(record.getMessage()) if isinstance(record.getMessage(), str) and record.getMessage().startswith('{') else {"text": record.getMessage()},
            "event.dataset": record.__dict__.get("event_dataset", None),
            "log.file.path": record.__dict__.get("log_file_path", "unknown")
        }
        # Remove event.dataset if it's None to avoid conflicts
        if log_record["event.dataset"] is None:
            del log_record["event.dataset"]
        return json.dumps(log_record)

# Initialize loggers
system_logger = logging.getLogger("system_logger")
general_logger = logging.getLogger("general_logger")
exploit_logger = logging.getLogger("exploit_logger")
t3_logger = logging.getLogger("t3_logger")

# Set log level and handlers for each logger
for logger in [system_logger, general_logger, exploit_logger, t3_logger]:
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(ECSFormatter())
    logger.addHandler(handler)

# Add file handlers to loggers
log_file_paths = {
    "system_logger": "logs/system.log",
    "general_logger": "logs/general_events.log",
    "exploit_logger": "logs/exploit_events.log",
    "t3_logger": "logs/t3_events.log"
}

for logger_name, log_file in log_file_paths.items():
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(ECSFormatter())
    globals()[logger_name].addHandler(file_handler)

def log_event(logger, level, message, extra):
    # Add extra fields to the log record
    extra = extra or {}
    logger_adapter = logging.LoggerAdapter(logger, extra)
    if level == 'info':
        logger_adapter.info(message)
    elif level == 'error':
        logger_adapter.error(message)
    elif level == 'warning':
        logger_adapter.warning(message)