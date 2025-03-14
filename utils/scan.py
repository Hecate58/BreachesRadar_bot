import logging
import re
import json
import socket
import requests
import asyncio
import whois
import dns.resolver
from config import (
    VIRUSTOTAL_API_KEY,
    URLSCAN_API_KEY,
    COMMON_PORTS_TO_SCAN,
    REQUEST_TIMEOUT
)

logger = logging.getLogger(__name__)

async def scan_domain(domain):
    """Fonction pour scanner un domaine"""
    results = []
    
    # Récupérer les informations WHOIS
    try:
        domain_info = whois.whois(domain)
        whois_data = {
            'registrar': domain_info.registrar if hasattr(domain_info, 'registrar') else "Non disponible",
            'creation_date': str(domain_info.creation_date) if hasattr(domain_info, 'creation_date') else "Non disponible",
            'expiration_date': str(domain_info.expiration_date) if hasattr(domain_info, 'expiration_date') else "Non disponible",
            'name_servers': ", ".join(domain_info.name_servers) if hasattr(domain_info, 'name_servers') else "Non disponible"
        }
        
        results.append({
            'title': 'Informations WHOIS',
            'details': whois_data,
            'source': 'WHOIS'
        })
    except Exception as e:
        logger.error(f"Erreur lors de la récupération WHOIS: {str(e)}")
        results.append({
            'title': 'Erreur lors de la récupération WHOIS',
            'details': {'error': str(e)},
            'source': 'Error'
        })
    
    # DNS Lookup
    try:
        dns_records = {}
        record_types = ['A', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                records = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = [record.to_text() for record in records]
            except Exception:
                dns_records[record_type] = ["Non disponible"]
        
        results.append({
            'title': 'Enregistrements DNS',
            'details': dns_records,
            'source': 'DNS Lookup'
        })
    except Exception as e:
        logger.error(f"Erreur lors de la récupération DNS: {str(e)}")
        results.append({
            'title': 'Erreur lors de la récupération DNS',
            'details': {'error': str(e)},
            'source': 'Error'
        })
    
    # Vérification VirusTotal
    if VIRUSTOTAL_API_KEY != "your_virustotal_api_key":
        try:
            vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            response = requests.get(vt_url, headers=headers, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                last_analysis_stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                vt_data = {
                    'malicious': last_analysis_stats.get('malicious', 0),
                    'suspicious': last_analysis_stats.get('suspicious', 0),
                    'harmless': last_analysis_stats.get('harmless', 0),
                    'undetected': last_analysis_stats.get('undetected', 0)
                }
                
                results.append({
                    'title': 'Analyse VirusTotal',
                    'details': vt_data,
                    'source': 'VirusTotal'
                })
            else:
                results.append({
                    'title': 'Erreur VirusTotal API',
                    'details': {'error': f"Code d'erreur: {response.status_code}"},
                    'source': 'Error'
                })
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse VirusTotal: {str(e)}")
            results.append({
                'title': 'Erreur lors de l\'analyse VirusTotal',
                'details': {'error': str(e)},
                'source': 'Error'
            })
    
    # Scan de ports basique
    try:
        open_ports = []
        
        for port in COMMON_PORTS_TO_SCAN:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((domain, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown"
                open_ports.append(f"{port} ({service})")
            sock.close()
        
        if open_ports:
            results.append({
                'title': 'Ports ouverts',
                'details': {'open_ports': open_ports},
                'source': 'Port Scan'
            })
        else:
            results.append({
                'title': 'Ports ouverts',
                'details': {'info': "Aucun port commun ouvert détecté"},
                'source': 'Port Scan'
            })
    except Exception as e:
        logger.error(f"Erreur lors du scan de ports: {str(e)}")
        results.append({
            'title': 'Erreur lors du scan de ports',
            'details': {'error': str(e)},
            'source': 'Error'
        })
    
    return results

async def scan_url(url):
    """Fonction pour scanner une URL"""
    results = []
    
    # Analyse des en-têtes HTTP
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.head(url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        
        security_headers = {
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', 'Non présent'),
            'Content-Security-Policy': response.headers.get('Content-Security-Policy', 'Non présent'),
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options', 'Non présent'),
            'X-Frame-Options': response.headers.get('X-Frame-Options', 'Non présent'),
            'X-XSS-Protection': response.headers.get('X-XSS-Protection', 'Non présent'),
            'Referrer-Policy': response.headers.get('Referrer-Policy', 'Non présent'),
            'Server': response.headers.get('Server', 'Non divulgué')
        }
        
        # Évaluation de la sécurité des en-têtes
        security_score = 0
        security_tips = []
        
        if 'Strict-Transport-Security' in response.headers:
            security_score += 1
        else:
            security_tips.append("HSTS manquant - Ajoutez l'en-tête Strict-Transport-Security")
            
        if 'Content-Security-Policy' in response.headers:
            security_score += 1
        else:
            security_tips.append("CSP manquant - Ajoutez une politique Content-Security-Policy")
            
        if response.headers.get('X-Content-Type-Options') == 'nosniff':
            security_score += 1
        else:
            security_tips.append("X-Content-Type-Options manquant - Ajoutez 'nosniff'")
            
        if 'X-Frame-Options' in response.headers:
            security_score += 1
        else:
            security_tips.append("X-Frame-Options manquant - Protégez contre le clickjacking")
            
        results.append({
            'title': 'En-têtes de sécurité',
            'details': security_headers,
            'source': 'HTTP Headers'
        })
        
        results.append({
            'title': 'Évaluation de sécurité',
            'details': {
                'score': f"{security_score}/4",
                'recommandations': security_tips
            },
            'source': 'Security Check'
        })
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse des en-têtes: {str(e)}")
        results.append({
            'title': 'Erreur lors de l\'analyse des en-têtes',
            'details': {'error': str(e)},
            'source': 'Error'
        })
    
    # Analyse URLScan.io
    if URLSCAN_API_KEY != "your_urlscan_api_key":
        try:
            headers = {'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json'}
            data = {"url": url, "visibility": "public"}
            response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data), timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                scan_data = response.json()
                results.append({
                    'title': 'Scan URLScan.io soumis',
                    'details': {
                        'scan_id': scan_data.get('uuid', 'Inconnu'),
                        'result_url': scan_data.get('result', 'Résultat non disponible'),
                        'status': 'Scan en cours, les résultats seront disponibles dans quelques minutes'
                    },
                    'source': 'URLScan.io'
                })
            else:
                results.append({
                    'title': 'Erreur URLScan.io API',
                    'details': {'error': f"Code d'erreur: {response.status_code}"},
                    'source': 'Error'
                })
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse URLScan.io: {str(e)}")
            results.append({
                'title': 'Erreur lors de l\'analyse URLScan.io',
                'details': {'error': str(e)},
                'source': 'Error'
            })
    
    # Analyse VirusTotal
    if VIRUSTOTAL_API_KEY != "your_virustotal_api_key":
        try:
            # Obtenir l'ID de ressource en soumettant l'URL
            vt_url = "https://www.virustotal.com/api/v3/urls"
            payload = {"url": url}
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            response = requests.post(vt_url, data=payload, headers=headers, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get('data', {}).get('id', '')
                if analysis_id:
                    # Attendre 2 secondes pour que l'analyse soit traitée
                    await asyncio.sleep(2)
                    
                    # Récupérer les résultats de l'analyse
                    result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    result_response = requests.get(result_url, headers=headers, timeout=REQUEST_TIMEOUT)
                    
                    if result_response.status_code == 200:
                        result_data = result_response.json()
                        stats = result_data.get('data', {}).get('attributes', {}).get('stats', {})
                        
                        vt_data = {
                            'malicious': stats.get('malicious', 0),
                            'suspicious': stats.get('suspicious', 0),
                            'harmless': stats.get('harmless', 0),
                            'undetected': stats.get('undetected', 0)
                        }
                        
                        results.append({
                            'title': 'Analyse VirusTotal',
                            'details': vt_data,
                            'source': 'VirusTotal'
                        })
                    else:
                        results.append({
                            'title': 'Erreur VirusTotal API (résultats)',
                            'details': {'error': f"Code d'erreur: {result_response.status_code}"},
                            'source': 'Error'
                        })
            else:
                results.append({
                    'title': 'Erreur VirusTotal API (soumission)',
                    'details': {'error': f"Code d'erreur: {response.status_code}"},
                    'source': 'Error'
                })
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse VirusTotal: {str(e)}")
            results.append({
                'title': 'Erreur lors de l\'analyse VirusTotal',
                'details': {'error': str(e)},
                'source': 'Error'
            })
    
    return results

async def scan_email(email):
    """Fonction pour scanner un email"""
    results = []
    
    # Validation basique de format d'email
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        results.append({
            'title': 'Validation du format',
            'details': {'error': "Le format de l'adresse email est invalide"},
            'source': 'Format Check'
        })
        return results
    
    # Extraction du domaine
    domain = email.split('@')[1]
    
    # Vérification MX du domaine
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_hosts = [record.exchange.to_text() for record in mx_records]
        
        results.append({
            'title': 'Enregistrements MX',
            'details': {'mx_records': mx_hosts},
            'source': 'DNS Check'
        })
        
        # Si des enregistrements MX sont trouvés, le domaine peut recevoir des emails
        results.append({
            'title': 'Validation du domaine',
            'details': {'status': 'Le domaine peut recevoir des emails'},
            'source': 'Domain Check'
        })
    except Exception as e:
        logger.error(f"Erreur lors de la vérification MX: {str(e)}")
        results.append({
            'title': 'Erreur lors de la vérification MX',
            'details': {'error': str(e), 'status': 'Le domaine pourrait ne pas être capable de recevoir des emails'},
            'source': 'Error'
        })
    
    # Vérification SPF et DMARC
    try:
        # SPF
        try:
            spf_records = dns.resolver.resolve(domain, 'TXT')
            spf_found = False
            
            for record in spf_records:
                if 'v=spf1' in record.to_text():
                    results.append({
                        'title': 'Enregistrement SPF',
                        'details': {'spf_record': record.to_text()},
                        'source': 'SPF Check'
                    })
                    spf_found = True
                    break
            
            if not spf_found:
                results.append({
                    'title': 'Enregistrement SPF',
                    'details': {'warning': 'Aucun enregistrement SPF trouvé'},
                    'source': 'SPF Check'
                })
        except Exception as spf_err:
            logger.error(f"Erreur lors de la vérification SPF: {str(spf_err)}")
            results.append({
                'title': 'Enregistrement SPF',
                'details': {'error': 'Impossible de récupérer les enregistrements SPF'},
                'source': 'Error'
            })
        
        # DMARC
        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            dmarc_found = False
            
            for record in dmarc_records:
                if 'v=DMARC1' in record.to_text():
                    results.append({
                        'title': 'Enregistrement DMARC',
                        'details': {'dmarc_record': record.to_text()},
                        'source': 'DMARC Check'
                    })
                    dmarc_found = True
                    break
            
            if not dmarc_found:
                results.append({
                    'title': 'Enregistrement DMARC',
                    'details': {'warning': 'Aucun enregistrement DMARC trouvé'},
                    'source': 'DMARC Check'
                })
        except Exception:
            results.append({
                'title': 'Enregistrement DMARC',
                'details': {'warning': 'Aucun enregistrement DMARC trouvé'},
                'source': 'DMARC Check'
            })
    except Exception as e:
        logger.error(f"Erreur lors de la vérification des enregistrements de sécurité: {str(e)}")
        results.append({
            'title': 'Erreur lors de la vérification des enregistrements de sécurité',
            'details': {'error': str(e)},
            'source': 'Error'
        })
    
    # Essayer de vérifier si l'email a été impliqué dans des fuites de données
    # Notez que sans API payante, c'est difficile à implémenter de manière fiable
    results.append({
        'title': 'Vérification de fuites de données',
        'details': {'info': "Pour vérifier si cet email a été impliqué dans des fuites de données, utilisez des services comme Have I Been Pwned ou Firefox Monitor"},
        'source': 'Info'
    })
    
    return results