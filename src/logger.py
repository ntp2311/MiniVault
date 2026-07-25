import logging
import os
from logging.handlers import RotatingFileHandler

LOG_DIR = "data/logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

log_file = os.path.join(LOG_DIR, "minivault.log")

# Configure logger
logger = logging.getLogger("minivault")
logger.setLevel(logging.INFO)

# Create a rotating file handler
handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)
