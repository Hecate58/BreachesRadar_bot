import logging
import re
import requests
from bs4 import BeautifulSoup
import praw
from config import (
    REDDIT_CLIENT_ID, 
    REDDIT_USER_AGENT, 
    GITHUB_TOKEN,
    MAX_SEARCH_RESULTS,
    REQUEST_TIMEOUT
)

logger = logging.getLogger(__name__)

# Collections de dorks catégorisées
DORKS_CATEGORIES = {
    "file_types": "Dorks pour la recherche de types de fichiers spécifiques",
    "sensitive": "Dorks pour trouver des informations sensibles",
    "cloud": "Dorks pour trouver des instances cloud exposées",
    "admin": "Dorks pour trouver des panneaux d'administration",
    "databases": "Dorks pour trouver des bases de données exposées",
    "cms": "Dorks pour des vulnérabilités CMS",
    "cctv": "Dorks pour trouver des caméras CCTV exposées",
    "git": "Dorks pour trouver des fichiers Git exposés",
    "logs": "Dorks pour trouver des fichiers de logs"
}

# Dorks par catégories
FILE_TYPE_DORKS = [
    "site:{domain} ext:pdf",
    "site:{domain} ext:doc | ext:docx | ext:odt",
    "site:{domain} ext:xls | ext:xlsx | ext:csv",
    "site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini | ext:env",
    "site:{domain} ext:sql | ext:dbf | ext:mdb | ext:db",
    "site:{domain} ext:log",
    "site:{domain} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup"
]

SENSITIVE_DATA_DORKS = [
    "site:{domain} intext:\"password\" | intext:\"username\"",
    "site:{domain} intext:\"password\" filetype:txt | filetype:log | filetype:sql | filetype:env",
    "site:{domain} intext:\"API_KEY\" | intext:\"api_secret\" | intext:\"client_secret\" | intext:\"authToken\"",
    "site:{domain} intext:\"BEGIN CERTIFICATE\" | intext:\"PRIVATE KEY\"",
    "site:{domain} intext:\"confidential\" filetype:pdf | filetype:docx",
    "site:{domain} intext:\"internal use only\" | intext:\"not for distribution\"",
    "site:{domain} intext:\"SELECT FROM\" | intext:\"UNION SELECT\" | intext:\"INSERT INTO\"",
    "site:{domain} intext:\"sql syntax near\" | intext:\"syntax error has occurred\" | intext:\"incorrect syntax near\"",
    "site:{domain} ext:sql intext:\"INSERT INTO\"",
    "site:{domain} intext:\"error\" | intext:\"warning\" | intext:\"syntax error\""
]

CLOUD_INSTANCE_DORKS = [
    "site:{domain} inurl:s3.amazonaws.com | inurl:storage.googleapis.com | inurl:amazonaws.com",
    "site:{domain} ext:pem | ext:key intext:PRIVATE",
    "site:{domain} intext:\"_key\" | intext:\"_secret\" | intext:\"_token\"",
    "site:{domain} intext:\"aws_access_key_id\" | intext:\"AKIA\"",
    "site:{domain} intext:\"azure_storage_account\" | intext:\"blob.core.windows.net\"",
    "site:{domain} intext:\"gcp\" | intext:\"gs://\" | intext:\"storage.cloud.google\""
]

ADMIN_PANEL_DORKS = [
    "site:{domain} inurl:admin | inurl:administrator | inurl:login | inurl:backend | inurl:adm",
    "site:{domain} intitle:\"control panel\" | intitle:\"admin panel\" | intitle:\"dashboard\"",
    "site:{domain} inurl:wp-login | inurl:wp-admin",
    "site:{domain} inurl:cpanel | inurl:webmail",
    "site:{domain} inurl:phpmyadmin | inurl:server-status | inurl:status",
    "site:{domain} inurl:admin intext:username | intext:password"
]

DATABASE_DORKS = [
    "site:{domain} intitle:\"Index of\" intext:\"mysql.properties\" | intext:\"database.properties\"",
    "site:{domain} intitle:\"Index of\" intext:\"database\" | intext:\"db\" | intext:\"data\"",
    "site:{domain} inurl:phpmyadmin | inurl:adminer | inurl:sqladmin",
    "site:{domain} intitle:\"MongoDB\" intext:\"MongoDB shell\"",
    "site:{domain} ext:sql | ext:dump | ext:mysql",
    "site:{domain} intitle:\"Index of\" intext:\"backup-\" | intext:\"sql.gz\""
]

CMS_DORKS = [
    "site:{domain} inurl:wp-content | inurl:wp-includes",
    "site:{domain} inurl:wp-config.php",
    "site:{domain} inurl:configuration.php intext:\"var $password\"",
    "site:{domain} inurl:joomla | inurl:administrator",
    "site:{domain} inurl:drupal | inurl:node | inurl:modules",
    "site:{domain} inurl:magento | inurl:downloader | inurl:admin"
]

CCTV_DORKS = [
    "site:{domain} intitle:\"webcamxp\" | intitle:\"webcam 7\"",
    "site:{domain} inurl:\"ViewerFrame?Mode=\"",
    "site:{domain} intitle:\"Live View / - AXIS\" | inurl:view/view.shtml",
    "site:{domain} intitle:\"WEBCAM\" inurl:camara",
    "site:{domain} intitle:\"netcam\" intitle:\"camera\"",
    "site:{domain} (intitle:\"MJPG-Streamer\" | intext:\"MJPG-Streamer\")"
]

GIT_DORKS = [
    "site:{domain} inurl:\".git\" -intext:\"git\"",
    "site:{domain} inurl:\".git/config\"",
    "site:{domain} inurl:\".git/HEAD\"",
    "site:{domain} intext:\"Index of /.git\"",
    "site:{domain} inurl:\"/.git/objects/\"",
    "site:{domain} filename:.gitignore"
]

LOG_DORKS = [
    "site:{domain} ext:log",
    "site:{domain} filetype:log intext:\"error\" | intext:\"warning\"",
    "site:{domain} inurl:/logs/ | inurl:/log/",
    "site:{domain} ext:log intext:\"password\" | intext:\"username\"",
    "site:{domain} intitle:\"Index of\" intext:\"error_log\" | intext:\"access_log\"",
    "site:{domain} intext:\"PHP Parse error\" | intext:\"PHP Warning\""
]

# Mapping des catégories aux listes de dorks
DORKS_MAPPING = {
    "file_types": FILE_TYPE_DORKS,
    "sensitive": SENSITIVE_DATA_DORKS,
    "cloud": CLOUD_INSTANCE_DORKS,
    "admin": ADMIN_PANEL_DORKS,
    "databases": DATABASE_DORKS,
    "cms": CMS_DORKS,
    "cctv": CCTV_DORKS,
    "git": GIT_DORKS,
    "logs": LOG_DORKS
}

# Fonction pour nettoyer le texte des balises HTML non supportées par Telegram
def clean_for_telegram(text):
    """Nettoie le texte pour qu'il soit compatible avec le HTML de Telegram"""
    if not text:
        return ""
        
    # Convertir text en string s'il ne l'est pas déjà
    text = str(text)
    
    # Remplacer les balises <br> par des sauts de ligne
    text = text.replace('<br>', '\n')
    
    # Échapper les caractères spéciaux HTML
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    
    # Restaurer les balises HTML supportées par Telegram
    allowed_tags = ['b', 'i', 'u', 'code', 'pre', 'a', 's']
    for tag in allowed_tags:
        # Balise ouvrante
        text = text.replace(f'&lt;{tag}&gt;', f'<{tag}>')
        text = text.replace(f'&lt;{tag} ', f'<{tag} ')
        # Balise fermante
        text = text.replace(f'&lt;/{tag}&gt;', f'</{tag}>')
    
    return text

async def search_web(query):
    """Fonction de recherche web basique sans API payante"""
    results = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    
    try:
        # Recherche DuckDuckGo (sans API)
        search_url = f"https://html.duckduckgo.com/html/?q={query}"
        response = requests.get(search_url, headers=headers, timeout=REQUEST_TIMEOUT)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            search_results = soup.find_all('div', class_='result')
            
            for result in search_results[:MAX_SEARCH_RESULTS]:
                title_elem = result.find('a', class_='result__a')
                if title_elem:
                    title = title_elem.text.strip()
                    url = title_elem.get('href', '')
                    
                    # Nettoyer l'URL de DuckDuckGo
                    if 'duckduckgo.com' in url:
                        url_match = re.search(r'uddg=(.*?)&', url)
                        if url_match:
                            url = requests.utils.unquote(url_match.group(1))
                    
                    snippet_elem = result.find('a', class_='result__snippet')
                    snippet = snippet_elem.text.strip() if snippet_elem else "Pas de description disponible"
                    
                    # Nettoyer le snippet pour Telegram
                    snippet = clean_for_telegram(snippet)
                    title = clean_for_telegram(title)
                    
                    results.append({
                        'title': title,
                        'url': url,
                        'snippet': snippet,
                        'source': 'DuckDuckGo'
                    })
    except Exception as e:
        logger.error(f"Erreur lors de la recherche web: {str(e)}")
        results.append({
            'title': 'Erreur de recherche',
            'url': '',
            'snippet': f"Une erreur s'est produite: {str(e)}",
            'source': 'Error'
        })
    
    return results

async def search_reddit(query):
    """Fonction de recherche sur Reddit utilisant PRAW"""
    results = []
    try:
        reddit = praw.Reddit(
            client_id=REDDIT_CLIENT_ID,
            user_agent=REDDIT_USER_AGENT,
            client_secret="",  # Peut être vide pour une utilisation read-only
        )
        
        # Recherche dans les posts
        search_results = reddit.subreddit("all").search(query, limit=MAX_SEARCH_RESULTS)
        
        for post in search_results:
            # Nettoyer le texte pour Telegram
            title = clean_for_telegram(post.title)
            selftext = clean_for_telegram(post.selftext)
            
            results.append({
                'title': title,
                'url': f"https://www.reddit.com{post.permalink}",
                'snippet': selftext[:150] + "..." if len(selftext) > 150 else selftext,
                'source': f"r/{post.subreddit.display_name}"
            })
    except Exception as e:
        logger.error(f"Erreur lors de la recherche Reddit: {str(e)}")
        results.append({
            'title': 'Erreur de recherche Reddit',
            'url': '',
            'snippet': f"Une erreur s'est produite: {str(e)}",
            'source': 'Error'
        })
    
    return results

async def search_github(query):
    """Fonction de recherche sur GitHub"""
    results = []
    headers = {'User-Agent': 'Mozilla/5.0', 'Authorization': f'token {GITHUB_TOKEN}'} if GITHUB_TOKEN != "your_github_token" else {'User-Agent': 'Mozilla/5.0'}
    
    try:
        search_url = f"https://api.github.com/search/repositories?q={query}&sort=stars&order=desc"
        response = requests.get(search_url, headers=headers, timeout=REQUEST_TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            
            for repo in data.get('items', [])[:MAX_SEARCH_RESULTS]:
                # Nettoyer la description pour Telegram
                name = clean_for_telegram(repo['name'])
                description = clean_for_telegram(repo.get('description', '')) if repo.get('description') else "Pas de description disponible"
                owner = clean_for_telegram(repo['owner']['login'])
                
                results.append({
                    'title': name,
                    'url': repo['html_url'],
                    'snippet': description,
                    'source': f"GitHub - {owner}"
                })
        else:
            results.append({
                'title': 'Erreur GitHub API',
                'url': '',
                'snippet': f"Code d'erreur: {response.status_code}",
                'source': 'Error'
            })
    except Exception as e:
        logger.error(f"Erreur lors de la recherche GitHub: {str(e)}")
        results.append({
            'title': 'Erreur de recherche GitHub',
            'url': '',
            'snippet': f"Une erreur s'est produite: {str(e)}",
            'source': 'Error'
        })
    
    return results

async def search_google_dorks(dork, target_domain=None):
    """Fonction pour traiter les Google Dorks"""
    results = []
    
    # Extraction du domaine si possible
    domain = target_domain
    if not domain and "site:" in dork:
        domain_match = re.search(r'site:([^\s]+)', dork)
        if domain_match:
            domain = domain_match.group(1)
    
    # Avertissement sur l'utilisation des dorks
    results.append({
        'title': 'Information sur les Google Dorks',
        'url': '',
        'snippet': "Les Google Dorks sont des requêtes spécialisées pour découvrir des informations sensibles sur des sites web. Utilisez-les uniquement sur des domaines pour lesquels vous avez une autorisation légale.",
        'source': 'Info'
    })
    
    # Opérateurs communs de Google Dorks
    common_operators = {
        'site:': 'Limiter la recherche à un domaine spécifique',
        'inurl:': 'Rechercher dans l\'URL',
        'intitle:': 'Rechercher dans le titre de la page',
        'filetype:': 'Rechercher un type de fichier spécifique',
        'intext:': 'Rechercher dans le texte de la page',
        'ext:': 'Rechercher par extension de fichier',
        'cache:': 'Afficher la version en cache d\'une page',
        'link:': 'Trouver des pages qui contiennent un lien vers l\'URL spécifiée',
        'related:': 'Trouver des sites similaires',
        'info:': 'Obtenir des informations sur une page'
    }
    
    # Détection de la structure du dork fourni
    detected_operators = []
    
    for operator in common_operators:
        if operator in dork:
            detected_operators.append(operator)
    
    # Construction de suggestions
    if detected_operators:
        operator_info = ", ".join([f"{op} ({common_operators[op]})" for op in detected_operators])
        suggestion = f"Dork analysé: {dork}\n\nOpérateurs détectés: {operator_info}"
    else:
        suggestion = f"Aucun opérateur de dork détecté dans '{dork}'. Pour formuler un dork efficace, utilisez des opérateurs comme site:, inurl:, etc."
    
    results.append({
        'title': 'Analyse du Dork',
        'url': '',
        'snippet': suggestion,
        'source': 'Analyse'
    })
    
    # Si un domaine est détecté, suggérer des dorks par catégorie
    if domain:
        results.append({
            'title': 'Dorks suggérés par catégorie',
            'url': '',
            'snippet': f"Voici des suggestions de dorks pour le domaine {domain}. Utilisez-les avec un moteur de recherche pour découvrir des vulnérabilités potentielles.",
            'source': 'Suggestions'
        })
        
        # Ajouter des exemples de dorks par catégorie pour le domaine spécifié
        for category, description in DORKS_CATEGORIES.items():
            category_dorks = DORKS_MAPPING.get(category, [])
            formatted_dorks = [d.format(domain=domain) for d in category_dorks[:3]]  # Limiter à 3 exemples par catégorie
            
            if formatted_dorks:
                # Utiliser des sauts de ligne (\n) au lieu de balises <br>
                dorks_text = "\n".join(formatted_dorks)
                results.append({
                    'title': f'Catégorie: {category}',
                    'url': '',
                    'snippet': f"{description}\n\nExemples:\n{dorks_text}",
                    'source': 'Exemples'
                })
    else:
        # Suggestions génériques de dorks de sécurité
        security_dorks = [
            "site:example.com filetype:pdf",
            "site:example.com intext:password",
            "site:example.com ext:sql OR ext:db OR ext:backup",
            "site:example.com intitle:\"Index of\"",
            "site:example.com inurl:admin",
            "site:example.com ext:log",
            "site:example.com intext:\"sql syntax near\" | intext:\"syntax error has occurred\"",
            "site:example.com \"PHP Parse error\" | \"PHP Warning\" | \"PHP Error\""
        ]
        
        # Utiliser des sauts de ligne (\n) au lieu de balises <br>
        dorks_text = "\n".join(security_dorks)
        results.append({
            'title': 'Exemples de dorks pour la sécurité',
            'url': '',
            'snippet': f"Remplacez example.com par votre domaine cible:\n\n{dorks_text}",
            'source': 'Exemples'
        })
    
    # Ajouter des ressources pour en savoir plus
    resources_text = (
        "Pour découvrir plus de dorks et améliorer vos compétences:\n\n"
        "• ExploitDB Google Hacking Database (GHDB)\n"
        "• Github: BullsEye0/google_dork_list\n"
        "• Github: cipher387/Dorks-collections-list\n"
        "• IntelTechniques.com - Moteurs de recherche\n"
        "• OSINT Framework - Dorks"
    )
    results.append({
        'title': 'Ressources pour les Google Dorks',
        'url': '',
        'snippet': resources_text,
        'source': 'Ressources'
    })
    
    return results

# Nouvelle fonction pour obtenir des dorks par catégorie
async def get_dorks_by_category(category, domain=None):
    """Obtenir des dorks pour une catégorie spécifique"""
    results = []
    
    if category in DORKS_MAPPING:
        dorks_list = DORKS_MAPPING[category]
        description = DORKS_CATEGORIES.get(category, "Dorks pour cette catégorie")
        
        # Formater les dorks avec le domaine si fourni
        if domain:
            formatted_dorks = [dork.format(domain=domain) for dork in dorks_list]
        else:
            formatted_dorks = dorks_list
        
        # Utiliser des sauts de ligne (\n) au lieu de balises <br>
        dorks_text = "\n".join(formatted_dorks)
        results.append({
            'title': f'Dorks pour la catégorie: {category}',
            'url': '',
            'snippet': f"{description}\n\n{dorks_text}",
            'source': 'Catégorie'
        })
    else:
        # Si la catégorie n'existe pas, renvoyer la liste des catégories disponibles
        categories_list = "\n".join([f"• {key}: {value}" for key, value in DORKS_CATEGORIES.items()])
        
        results.append({
            'title': 'Catégorie non trouvée',
            'url': '',
            'snippet': f"La catégorie '{category}' n'existe pas. Voici les catégories disponibles:\n\n{categories_list}",
            'source': 'Erreur'
        })
    
    return results

# Nouvelle fonction pour une recherche rapide multi-catégories
async def quick_dork_scan(domain):
    """Effectue un scan rapide en utilisant des dorks de différentes catégories"""
    results = []
    
    # Sélectionner des dorks représentatifs de chaque catégorie
    representative_dorks = {
        "Fichiers sensibles": [
            f"site:{domain} ext:pdf | ext:doc | ext:xls | ext:ppt",
            f"site:{domain} ext:sql | ext:bak | ext:backup"
        ],
        "Informations d'authentification": [
            f"site:{domain} intext:\"password\" | intext:\"username\"",
            f"site:{domain} intext:\"API_KEY\" | intext:\"api_secret\""
        ],
        "Infrastructure": [
            f"site:{domain} inurl:admin | inurl:login | inurl:wp-admin",
            f"site:{domain} intitle:\"Index of\" | intitle:\"Directory Listing\""
        ],
        "Erreurs et fuites": [
            f"site:{domain} intext:\"error\" | intext:\"warning\" | intext:\"syntax error\"",
            f"site:{domain} intext:\"SQL syntax\""
        ]
    }
    
    for category, dorks in representative_dorks.items():
        # Utiliser des sauts de ligne (\n) au lieu de balises <br>
        dorks_text = "\n".join(dorks)
        results.append({
            'title': f'Scan rapide: {category}',
            'url': '',
            'snippet': dorks_text,
            'source': 'QuickScan'
        })
    
    return results