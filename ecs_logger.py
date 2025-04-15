import logging
import json
from datetime import datetime

class ECSFormatter(logging.Formatter):
    def format(self, record):
        # Ensure the log record is serialized as a clean JSON object
        log_record = {
            "@timestamp": record.created,
            "log.level": record.levelname.lower(),
            "message": record.getMessage(),
            "event.dataset": record.__dict__.get("event_dataset", "default")
        }
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