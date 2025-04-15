import logging
import json
from pythonjsonlogger import jsonlogger
from datetime import datetime

# Configure ECS-compliant JSON logger
def configure_logger(name, log_file, level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)

    handler = logging.FileHandler(log_file)
    formatter = jsonlogger.JsonFormatter(
        fmt='%(asctime)s %(levelname)s %(message)s',
        json_ensure_ascii=False
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger

# Create loggers
system_logger = configure_logger('system', 'logs/system.log')
general_logger = configure_logger('general_events', 'logs/general_events.log')
exploit_logger = configure_logger('exploit_events', 'logs/exploit_events.log')
t3_logger = configure_logger('t3_events', 'logs/t3_events.log')

# Helper function for ECS-compliant log entries
def log_event(logger, level, message, ecs_fields):
    log_entry = {
        "@timestamp": datetime.utcnow().isoformat(),
        "log.level": level,
        "message": message,
        **ecs_fields
    }
    if level == 'info':
        logger.info(json.dumps(log_entry))
    elif level == 'error':
        logger.error(json.dumps(log_entry))
    elif level == 'warning':
        logger.warning(json.dumps(log_entry))