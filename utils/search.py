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
            results.append({
                'title': post.title,
                'url': f"https://www.reddit.com{post.permalink}",
                'snippet': post.selftext[:150] + "..." if len(post.selftext) > 150 else post.selftext,
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
                results.append({
                    'title': repo['name'],
                    'url': repo['html_url'],
                    'snippet': repo['description'] if repo['description'] else "Pas de description disponible",
                    'source': f"GitHub - {repo['owner']['login']}"
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

async def search_google_dorks(dork):
    """Fonction pour traiter les Google Dorks"""
    results = []
    
    # Avertissement sur l'utilisation des dorks
    results.append({
        'title': 'Information sur les Google Dorks',
        'url': '',
        'snippet': "Les Google Dorks sont des requêtes spécialisées. Ce bot ne peut pas exécuter directement ces requêtes car cela pourrait violer les conditions d'utilisation de Google. Voici quelques conseils d'utilisation:",
        'source': 'Info'
    })
    
    # Suggestions de dorks courants basés sur la requête de l'utilisateur
    common_dorks = {
        'site:': 'Limiter la recherche à un domaine spécifique',
        'inurl:': 'Rechercher dans l\'URL',
        'intitle:': 'Rechercher dans le titre de la page',
        'filetype:': 'Rechercher un type de fichier spécifique',
        'intext:': 'Rechercher dans le texte de la page',
        'ext:': 'Rechercher par extension de fichier'
    }
    
    # Détection de la structure du dork fourni
    detected_operators = []
    suggestion = ""
    
    for operator in common_dorks:
        if operator in dork:
            detected_operators.append(operator)
    
    # Construction de suggestions
    if detected_operators:
        suggestion = f"Dork détecté: {' '.join(detected_operators)}\nCopier ce dork dans un moteur de recherche: {dork}"
    else:
        suggestion = f"Aucun opérateur de dork détecté. Voici comment formuler votre requête: site:example.com {dork}"
    
    results.append({
        'title': 'Suggestion de Google Dork',
        'url': '',
        'snippet': suggestion,
        'source': 'Suggestion'
    })
    
    # Ajouter des exemples de dorks utiles pour la sécurité
    security_dorks = [
        "site:target.com filetype:pdf",
        "site:target.com intext:password",
        "site:target.com ext:sql OR ext:db OR ext:backup",
        "site:target.com intitle:\"Index of\"",
        "site:target.com inurl:admin",
        "site:target.com ext:log",
        "site:target.com intext:\"sql syntax near\" | intext:\"syntax error has occurred\" | intext:\"incorrect syntax near\" | intext:\"unexpected end of SQL command\" | intext:\"Warning: mysql_connect()\" | intext:\"Warning: mysql_query()\" | intext:\"Warning: pg_connect()\"",
        "site:target.com \"PHP Parse error\" | \"PHP Warning\" | \"PHP Error\""
    ]
    
    results.append({
        'title': 'Dorks utiles pour la sécurité',
        'url': '',
        'snippet': "\n".join(security_dorks),
        'source': 'Exemples'
    })
    
    return results