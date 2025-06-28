"""
Configuration settings for SIGMA Detection Engineering Platform
"""

import os
from pathlib import Path

# Application settings
APP_NAME = "SIGMA Detection Engineering Platform"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "Comprehensive detection engineering platform with MITRE ATT&CK Explorer and SIGMA Rule Builder"

# Paths
PROJECT_ROOT = Path(__file__).parent
DATA_DIR = PROJECT_ROOT / "data"
DATABASE_DIR = DATA_DIR / "database"
SIGMA_RULES_DIR = DATA_DIR / "sigma_rules"
MITRE_DATA_DIR = DATA_DIR / "mitre_data"
LOGS_DIR = PROJECT_ROOT / "logs"

# Database settings
DATABASE_PATH = DATABASE_DIR / "sigma_platform.db"

# SIGMA repositories
SIGMA_REPOSITORIES = {
    'main': {
        'url': 'https://github.com/SigmaHQ/sigma.git',
        'rules_path': 'rules',
        'name': 'SigmaHQ Main Rules'
    },
    'threat-hunting': {
        'url': 'https://github.com/SigmaHQ/sigma.git',
        'rules_path': 'rules-threat-hunting',
        'name': 'SigmaHQ Threat Hunting Rules'
    },
    'emerging-threats': {
        'url': 'https://github.com/SigmaHQ/sigma.git',
        'rules_path': 'rules-emerging-threats',
        'name': 'SigmaHQ Emerging Threats'
    }
}

# MITRE ATT&CK data sources
MITRE_SOURCES = {
    'enterprise': 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
    'ics': 'https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json'
}

# LLM settings
DEFAULT_OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")

# Sync settings
AUTO_SYNC_ENABLED = os.getenv("AUTO_SYNC_ENABLED", "true").lower() == "true"
SYNC_INTERVAL_DAYS = int(os.getenv("SYNC_INTERVAL_DAYS", "7"))
MAX_SYNC_RETRIES = int(os.getenv("MAX_SYNC_RETRIES", "3"))

# Search settings
DEFAULT_SEARCH_LIMIT = int(os.getenv("DEFAULT_SEARCH_LIMIT", "100"))
MAX_SEARCH_RESULTS = int(os.getenv("MAX_SEARCH_RESULTS", "1000"))
SEMANTIC_SEARCH_THRESHOLD = float(os.getenv("SEMANTIC_SEARCH_THRESHOLD", "0.6"))

# UI settings
ITEMS_PER_PAGE = int(os.getenv("ITEMS_PER_PAGE", "20"))
MAX_DISPLAY_ITEMS = int(os.getenv("MAX_DISPLAY_ITEMS", "100"))

# Logging settings
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = os.getenv("LOG_FORMAT", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
LOG_FILE = LOGS_DIR / os.getenv("LOG_FILE", "sigma_platform.log")

# Security settings
ENABLE_CUSTOM_RULES = os.getenv("ENABLE_CUSTOM_RULES", "true").lower() == "true"
ALLOW_RULE_DELETION = os.getenv("ALLOW_RULE_DELETION", "true").lower() == "true"
REQUIRE_RULE_VALIDATION = os.getenv("REQUIRE_RULE_VALIDATION", "true").lower() == "true"

# Performance settings
ENABLE_CACHING = os.getenv("ENABLE_CACHING", "true").lower() == "true"
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "3600"))
MAX_CONCURRENT_SYNCS = int(os.getenv("MAX_CONCURRENT_SYNCS", "3"))

# Feature flags
ENABLE_AI_FEATURES = os.getenv("ENABLE_AI_FEATURES", "true").lower() == "true"
ENABLE_SEMANTIC_SEARCH = os.getenv("ENABLE_SEMANTIC_SEARCH", "true").lower() == "true"
ENABLE_ATTACK_MAPPING = os.getenv("ENABLE_ATTACK_MAPPING", "true").lower() == "true"
ENABLE_RULE_TESTING = os.getenv("ENABLE_RULE_TESTING", "false").lower() == "true"

def ensure_directories():
    """Ensure all required directories exist"""
    directories = [
        DATA_DIR,
        DATABASE_DIR,
        SIGMA_RULES_DIR,
        MITRE_DATA_DIR,
        LOGS_DIR
    ]
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)

def get_config():
    """Get configuration dictionary"""
    return {
        'app': {
            'name': APP_NAME,
            'version': APP_VERSION,
            'description': APP_DESCRIPTION
        },
        'paths': {
            'project_root': PROJECT_ROOT,
            'data_dir': DATA_DIR,
            'database_path': DATABASE_PATH,
            'logs_dir': LOGS_DIR
        },
        'sigma': {
            'repositories': SIGMA_REPOSITORIES,
            'auto_sync': AUTO_SYNC_ENABLED,
            'sync_interval': SYNC_INTERVAL_DAYS
        },
        'mitre': {
            'sources': MITRE_SOURCES
        },
        'llm': {
            'ollama_host': DEFAULT_OLLAMA_HOST,
            'ollama_model': DEFAULT_OLLAMA_MODEL
        },
        'search': {
            'default_limit': DEFAULT_SEARCH_LIMIT,
            'max_results': MAX_SEARCH_RESULTS,
            'semantic_threshold': SEMANTIC_SEARCH_THRESHOLD
        },
        'ui': {
            'items_per_page': ITEMS_PER_PAGE,
            'max_display_items': MAX_DISPLAY_ITEMS
        },
        'features': {
            'ai_features': ENABLE_AI_FEATURES,
            'semantic_search': ENABLE_SEMANTIC_SEARCH,
            'attack_mapping': ENABLE_ATTACK_MAPPING,
            'rule_testing': ENABLE_RULE_TESTING
        }
    }

# Initialize directories on import
ensure_directories()
