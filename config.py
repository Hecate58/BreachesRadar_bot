REDDIT_CLIENT_ID = "1znsRGrxUXp0stoWuc3_JA"  # obtenable gratuitement via https://www.reddit.com/prefs/apps
REDDIT_CLIENT_SECRET = None  # Optionnel 
REDDIT_USER_AGENT = "PythonSecurityBot/1.0"  # User-agent pour les requêtes Reddit
ALIENVAULT_API_KEY = None  # Optionnel - gratuit via https://otx.alienvault.com
GITHUB_TOKEN = 'your_github_token'
URLSCAN_API_KEY = '01958fa1-4181-7002-8768-500c7e53d586'
VIRUSTOTAL_API_KEY = "0f694fa53021b262eb7e32bd3afc0b5757012cdb619156a2c461f425fbdc8c22"  

import os

# Configuration des API
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8143357098:AAEZUsmztXNxwK8219JZX3-qaRXXqLfKiuY")

# API Reddit
REDDIT_CLIENT_ID = os.environ.get("REDDIT_CLIENT_ID", "1znsRGrxUXp0stoWuc3_JA")
REDDIT_CLIENT_SECRET = os.environ.get("REDDIT_CLIENT_SECRET", None)
REDDIT_USER_AGENT = os.environ.get("REDDIT_USER_AGENT", "PythonSecurityBot/1.0")

# API de sécurité
ALIENVAULT_API_KEY = os.environ.get("ALIENVAULT_API_KEY", None)
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "your_github_token")
URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "01958fa1-4181-7002-8768-500c7e53d586")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "0f694fa53021b262eb7e32bd3afc0b5757012cdb619156a2c461f425fbdc8c22")

# Configuration de logging
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = 'INFO'

# Etats de conversation pour Telegram
CHOOSE_SEARCH, CHOOSE_SCAN, DOMAIN_INPUT, EMAIL_INPUT, URL_INPUT, KEYWORD_INPUT, DORK_INPUT, GENERATE_REPORT = range(8)

# Autres configurations
MAX_SEARCH_RESULTS = 10
REQUEST_TIMEOUT = 10  # en secondes
COMMON_PORTS_TO_SCAN = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 3306, 3389, 8080, 8443]