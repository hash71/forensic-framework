"""Configuration and path management for the forensic framework."""

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from dotenv import load_dotenv

# Project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Load environment variables
load_dotenv(PROJECT_ROOT / ".env")

# Data paths
DATA_DIR = PROJECT_ROOT / "data"
SCENARIOS_DIR = DATA_DIR / "scenarios"
RAW_LOGS_DIR = DATA_DIR / "raw_logs"
NORMALIZED_DIR = DATA_DIR / "normalized"
GROUND_TRUTH_DIR = DATA_DIR / "ground_truth"
LLM_RESPONSES_DIR = DATA_DIR / "llm_responses"
CONFIG_DIR = PROJECT_ROOT / "config"

# LLM settings
MODAL_ENDPOINT = os.getenv("MODAL_ENDPOINT", "")
MODAL_TOKEN = os.getenv("MODAL_TOKEN", "")

# Timezone
TIMEZONE = "Asia/Dhaka"
UTC_OFFSET = "+06:00"


def setup_logging():
    """Configure application-wide logging."""
    log_dir = PROJECT_ROOT / "logs"
    log_dir.mkdir(exist_ok=True)

    logger = logging.getLogger("forensic")
    logger.setLevel(logging.DEBUG)

    # Console handler (INFO+)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S"))

    # File handler (DEBUG+, rotating)
    fh = RotatingFileHandler(log_dir / "forensic_framework.log", maxBytes=5*1024*1024, backupCount=3)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))

    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger
