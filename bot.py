import os
import logging
import asyncio
import re
from datetime import datetime

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler, ContextTypes, 
    ConversationHandler, MessageHandler, filters
)

# Importer les configurations
from config import (
    TELEGRAM_BOT_TOKEN, LOG_FORMAT, LOG_LEVEL,
    CHOOSE_SEARCH, CHOOSE_SCAN, DOMAIN_INPUT, EMAIL_INPUT, 
    URL_INPUT, KEYWORD_INPUT, DORK_INPUT, GENERATE_REPORT
)

# Importer les modules utilitaires
from utils.search import (
    search_web, search_reddit, search_github, search_google_dorks,
    get_dorks_by_category, DORKS_CATEGORIES
)
from utils.scan import scan_domain, scan_url, scan_email
from utils.report import generate_pdf_report

# Configuration des journaux
logging.basicConfig(
    format=LOG_FORMAT,
    level=getattr(logging, LOG_LEVEL)
)
logger = logging.getLogger(__name__)

# État de conversation supplémentaire pour les catégories de dorks
CHOOSE_DORK_CATEGORY = 11
DORK_DOMAIN_INPUT = 12

# Fonction pour créer le clavier en ligne pour la recherche
def get_search_keyboard():
    keyboard = [
        [
            InlineKeyboardButton("🌐 Web", callback_data="web"),
            InlineKeyboardButton("📱 Reddit", callback_data="reddit")
        ],
        [
            InlineKeyboardButton("💻 Github", callback_data="github"),
            InlineKeyboardButton("🔎 Dorks", callback_data="dorks_menu")
        ],
        [
            InlineKeyboardButton("❌ Annuler", callback_data="cancel")
        ]
    ]
    return InlineKeyboardMarkup(keyboard)

# Fonction pour créer le clavier des catégories de dorks
def get_dorks_categories_keyboard():
    keyboard = []
    
    # Organiser les catégories par paires
    categories = list(DORKS_CATEGORIES.keys())
    for i in range(0, len(categories), 2):
        row = []
        row.append(InlineKeyboardButton(categories[i], callback_data=f"dork_cat_{categories[i]}"))
        if i + 1 < len(categories):
            row.append(InlineKeyboardButton(categories[i+1], callback_data=f"dork_cat_{categories[i+1]}"))
        keyboard.append(row)
    
    # Ajouter une option pour saisir un dork personnalisé
    keyboard.append([
        InlineKeyboardButton("🔍 Dork personnalisé", callback_data="custom_dork")
    ])
    
    # Ajouter un bouton Retour
    keyboard.append([
        InlineKeyboardButton("⬅️ Retour", callback_data="back_to_search"),
        InlineKeyboardButton("❌ Annuler", callback_data="cancel")
    ])
    
    return InlineKeyboardMarkup(keyboard)

# Fonction pour créer le clavier en ligne pour le scan
def get_scan_keyboard():
    keyboard = [
        [
            InlineKeyboardButton("🌍 Domaine", callback_data="domain"),
            InlineKeyboardButton("🔗 URL", callback_data="url")
        ],
        [
            InlineKeyboardButton("✉️ Email", callback_data="email"),
            InlineKeyboardButton("❌ Annuler", callback_data="cancel")
        ]
    ]
    return InlineKeyboardMarkup(keyboard)

# Gestionnaires de commandes
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Envoie un message quand la commande /start est émise"""
    user = update.effective_user
    await update.message.reply_html(
        f"🌟 Bienvenue {user.mention_html()} ! 🌟\n\n"
        f"🛡️ Je suis votre assistant de cybersécurité personnel. Je peux vous aider à trouver des informations sensibles, analyser des vulnérabilités et générer des rapports détaillés.\n\n"
        f"📋 <b>Commandes principales:</b>\n\n"
        f"🔍 /recherche - Explorer le web, Reddit, GitHub ou utiliser des Dorks\n"
        f"🔒 /scan - Analyser la sécurité d'un domaine, URL ou email\n"
        f"📊 /rapport - Générer un rapport PDF professionnel\n"
        f"ℹ️ /aide - Afficher toutes les instructions détaillées\n\n"
        f"🔐 <b>Prêt à renforcer votre sécurité?</b> Commencez avec la commande /recherche ou /scan !"
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Envoie un message quand la commande /aide est émise"""
    await update.message.reply_text(
        "📚 <b>GUIDE D'UTILISATION</b> 📚\n\n"
        "🔍 <b>RECHERCHE</b> avec /recherche\n"
        "  • 🌐 <b>Web</b>: recherche sans API payante\n"
        "  • 📱 <b>Reddit</b>: explore les forums et discussions\n"
        "  • 💻 <b>GitHub</b>: trouve des dépôts de code pertinents\n"
        "  • 🔎 <b>Dorks</b>: techniques avancées de recherche par catégories\n\n"
        "🛡️ <b>SÉCURITÉ</b> avec /scan\n"
        "  • 🌍 <b>Domaine</b>: WHOIS, DNS, ports ouverts, menaces\n"
        "  • 🔗 <b>URL</b>: analyse des en-têtes, réputation, vulnérabilités\n"
        "  • ✉️ <b>Email</b>: validité, SPF, DMARC, sécurité\n\n"
        "📊 <b>RAPPORTS</b> avec /rapport\n"
        "  • Génère un PDF professionnel des derniers résultats\n"
        "  • Parfait pour documentation et partage\n\n"
        "❌ Pour annuler à tout moment, cliquez sur \"Annuler\"\n\n"
        "💡 <b>ASTUCE</b>: Utilisez les dorks par catégorie pour des recherches ciblées!",
        parse_mode='HTML'
    )

async def search_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gère la commande /recherche"""
    # Debug: Afficher l'état actuel de la conversation
    logger.debug(f"État de la conversation pour l'utilisateur {update.effective_user.id}: {context.user_data.get('conversation_state', 'Aucun')}")
    
    # Réinitialiser explicitement l'état de la conversation
    if 'conversation_state' in context.user_data:
        del context.user_data['conversation_state']
    
    keyboard = get_search_keyboard()
    await update.message.reply_text(
        "🔍 <b>MODE RECHERCHE ACTIVÉ</b> 🔍\n\n"
        "Choisissez votre méthode de recherche :\n"
        "• 🌐 <b>Web</b> - Recherche standard sur le web\n"
        "• 📱 <b>Reddit</b> - Exploration des discussions Reddit\n"
        "• 💻 <b>GitHub</b> - Recherche de code et projets\n"
        "• 🔎 <b>Dorks</b> - Recherche avancée par catégories",
        parse_mode='HTML',
        reply_markup=keyboard
    )
    
    # Définir explicitement l'état de la conversation
    context.user_data['conversation_state'] = CHOOSE_SEARCH
    return CHOOSE_SEARCH

async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gère la commande /scan"""
    keyboard = get_scan_keyboard()
    await update.message.reply_text(
        "🛡️ <b>MODE ANALYSE DE SÉCURITÉ ACTIVÉ</b> 🛡️\n\n"
        "Choisissez ce que vous voulez analyser :\n"
        "• 🌍 <b>Domaine</b> - Analyse complète d'un domaine\n"
        "• 🔗 <b>URL</b> - Vérification de sécurité d'une URL\n"
        "• ✉️ <b>Email</b> - Validation et analyse d'email",
        parse_mode='HTML',
        reply_markup=keyboard
    )
    return CHOOSE_SCAN

async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gère la commande /rapport"""
    if not context.user_data.get('last_results'):
        await update.message.reply_text(
            "⚠️ <b>Aucune donnée disponible</b> ⚠️\n\n"
            "Vous devez d'abord effectuer une recherche ou un scan.\n"
            "Utilisez /recherche ou /scan pour commencer!",
            parse_mode='HTML'
        )
        return ConversationHandler.END
    
    await update.message.reply_text(
        "📊 <b>GÉNÉRATION DE RAPPORT EN COURS</b> 📊\n"
        "Préparation de votre document PDF...",
        parse_mode='HTML'
    )
    
    try:
        report_type = context.user_data.get('last_type', 'general')
        pdf_buffer = await generate_pdf_report(
            context.user_data['last_results'], 
            report_type
        )
        
        # Créer un nom de fichier personnalisé
        report_type_names = {
            'search': 'recherche',
            'domain': 'domaine',
            'url': 'url',
            'email': 'email',
            'general': 'general'
        }
        
        report_name = report_type_names.get(report_type, report_type)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        await update.message.reply_document(
            document=pdf_buffer,
            filename=f"SecScan_{report_name}_{timestamp}.pdf",
            caption="🔒 <b>RAPPORT DE SÉCURITÉ</b> 🔒\n\nVotre analyse détaillée est prête! Ce document peut être partagé ou sauvegardé pour référence future.",
            parse_mode='HTML'
        )
    except Exception as e:
        logger.error(f"Erreur lors de la génération du rapport: {str(e)}")
        await update.message.reply_text(
            f"❌ <b>ERREUR</b> ❌\n\nImpossible de générer le rapport: {str(e)}\n\nVeuillez réessayer ou contacter l'administrateur.",
            parse_mode='HTML'
        )
    
    return ConversationHandler.END

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gère les clics sur les boutons du clavier"""
    query = update.callback_query
    await query.answer()
    
    if query.data == "cancel":
        await query.edit_message_text(
            "❌ <b>OPÉRATION ANNULÉE</b> ❌\n\n"
            "Utilisez /recherche ou /scan pour commencer une nouvelle action.",
            parse_mode='HTML'
        )
        return ConversationHandler.END
    
    if query.data == "back_to_search":
        keyboard = get_search_keyboard()
        await query.edit_message_text(
            "🔍 <b>MODE RECHERCHE ACTIVÉ</b> 🔍\n\n"
            "Choisissez votre méthode de recherche :\n"
            "• 🌐 <b>Web</b> - Recherche standard sur le web\n"
            "• 📱 <b>Reddit</b> - Exploration des discussions Reddit\n"
            "• 💻 <b>GitHub</b> - Recherche de code et projets\n"
            "• 🔎 <b>Dorks</b> - Recherche avancée par catégories",
            parse_mode='HTML',
            reply_markup=keyboard
        )
        return CHOOSE_SEARCH
    
    # Afficher le menu des dorks
    if query.data == "dorks_menu":
        keyboard = get_dorks_categories_keyboard()
        await query.edit_message_text(
            "🔎 <b>CATÉGORIES DE DORKS</b> 🔎\n\n"
            "Choisissez une catégorie pour voir les dorks associés:\n\n"
            "<i>Les dorks sont des requêtes spécialisées pour découvrir des informations sensibles. Utilisez-les de manière éthique.</i>\n\n"
            "Sélectionnez une catégorie, puis vous pourrez spécifier un domaine cible:",
            parse_mode='HTML',
            reply_markup=keyboard
        )
        return CHOOSE_DORK_CATEGORY
    
    # Traiter les catégories de dorks
    if query.data.startswith("dork_cat_"):
        category = query.data.replace("dork_cat_", "")
        context.user_data['dork_category'] = category
        
        # Demander le domaine à l'utilisateur
        await query.edit_message_text(
            f"🔎 <b>DORKS - CATÉGORIE {category.upper()}</b> 🔎\n\n"
            f"<i>{DORKS_CATEGORIES.get(category, 'Dorks pour cette catégorie')}</i>\n\n"
            f"Veuillez entrer un domaine cible pour générer des dorks spécifiques:\n"
            f"<i>Exemple: example.com</i>\n\n"
            f"<i>Ou envoyez simplement un point (.) pour voir les dorks génériques.</i>",
            parse_mode='HTML'
        )
        return DORK_DOMAIN_INPUT
        
    # Option pour saisir un dork personnalisé
    if query.data == "custom_dork":
        await query.edit_message_text(
            f"🔎 <b>DORK PERSONNALISÉ</b> 🔎\n\n"
            f"Entrez votre dork ou mot-clé pour des suggestions avancées:\n\n"
            f"<i>Exemples:</i> <code>site:example.com filetype:pdf</code> ou <code>intext:password</code>",
            parse_mode='HTML'
        )
        return DORK_INPUT
    
    # Traiter les options de recherche web standard
    if query.data in ["web", "reddit", "github"]:
        context.user_data['search_type'] = query.data
        
        # Messages personnalisés selon le type de recherche
        search_icons = {
            'web': '🌐',
            'reddit': '📱',
            'github': '💻'
        }
        
        search_names = {
            'web': 'Web',
            'reddit': 'Reddit',
            'github': 'GitHub'
        }
        
        icon = search_icons.get(query.data, '🔍')
        name = search_names.get(query.data, 'Inconnu')
        
        await query.edit_message_text(
            f"{icon} <b>RECHERCHE {name.upper()}</b> {icon}\n\n"
            f"Entrez votre mot-clé ou phrase à rechercher:\n\n"
            f"<i>Soyez précis pour de meilleurs résultats!</i>",
            parse_mode='HTML'
        )
        return KEYWORD_INPUT
    
    # Traiter les options de scan
    if query.data in ["domain", "url", "email"]:
        context.user_data['scan_type'] = query.data
        
        # Messages personnalisés selon le type de scan
        scan_icons = {
            'domain': '🌍',
            'url': '🔗',
            'email': '✉️'
        }
        
        scan_names = {
            'domain': 'Domaine',
            'url': 'URL',
            'email': 'Email'
        }
        
        scan_examples = {
            'domain': 'example.com',
            'url': 'https://example.com/page',
            'email': 'utilisateur@example.com'
        }
        
        icon = scan_icons.get(query.data, '🔒')
        name = scan_names.get(query.data, 'Inconnu')
        example = scan_examples.get(query.data, '')
        
        if query.data == "domain":
            await query.edit_message_text(
                f"{icon} <b>ANALYSE DE {name.upper()}</b> {icon}\n\n"
                f"Entrez le nom de domaine à scanner:\n"
                f"<i>Format:</i> <code>{example}</code>\n\n"
                f"<i>L'analyse inclura WHOIS, DNS, ports et menaces connues.</i>",
                parse_mode='HTML'
            )
            return DOMAIN_INPUT
        elif query.data == "url":
            await query.edit_message_text(
                f"{icon} <b>ANALYSE DE {name.upper()}</b> {icon}\n\n"
                f"Entrez l'URL complète à scanner:\n"
                f"<i>Format:</i> <code>{example}</code>\n\n"
                f"<i>L'analyse vérifiera les en-têtes de sécurité et la réputation.</i>",
                parse_mode='HTML'
            )
            return URL_INPUT
        elif query.data == "email":
            await query.edit_message_text(
                f"{icon} <b>ANALYSE D'{name.upper()}</b> {icon}\n\n"
                f"Entrez l'adresse email à analyser:\n"
                f"<i>Format:</i> <code>{example}</code>\n\n"
                f"<i>L'analyse vérifiera la validité, SPF et DMARC.</i>",
                parse_mode='HTML'
            )
            return EMAIL_INPUT

async def dork_domain_input_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gère l'entrée du domaine pour les dorks de catégorie"""
    domain_input = update.message.text.strip()
    category = context.user_data.get('dork_category', '')
    
    # Si l'utilisateur a juste entré un point, utiliser des dorks génériques
    if domain_input == '.':
        domain = None
    else:
        # Nettoyer le domaine de tout protocole et chemin
        domain = domain_input
        # Supprimer le protocole (http:// ou https://)
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('://', 1)[1]
        # Supprimer tout ce qui suit un slash
        if '/' in domain:
            domain = domain.split('/', 1)[0]
    
    # Validation basique du domaine si fourni
    if domain:
        # Expression régulière améliorée pour accepter les domaines avec tirets
        domain_regex = r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
        if not re.match(domain_regex, domain, re.IGNORECASE):
            await update.message.reply_text(
                "⚠️ <b>FORMAT INVALIDE</b> ⚠️\n\n"
                "Le format du domaine n'est pas valide.\n"
                "Veuillez entrer un domaine au format correct (ex: example.com):",
                parse_mode='HTML'
            )
            return DORK_DOMAIN_INPUT
    
    # Log pour déboguer
    logger.debug(f"Domaine validé: {domain}")
    
    await update.message.reply_text(
        f"🔎 <b>GÉNÉRATION DE DORKS</b> 🔎\n\n"
        f"Catégorie: <code>{category}</code>\n"
        f"Domaine: <code>{domain if domain else 'Générique'}</code>\n"
        f"<i>Préparation des dorks, veuillez patienter...</i>",
        parse_mode='HTML'
    )
    
    try:
        results = await get_dorks_by_category(category, domain)
        
        if not results:
            await update.message.reply_text(
                f"❌ <b>CATÉGORIE NON TROUVÉE</b> ❌\n\n"
                f"La catégorie <code>{category}</code> n'existe pas ou ne contient pas de dorks.\n"
                f"Utilisez /recherche et sélectionnez 'Dorks' pour choisir une autre catégorie.",
                parse_mode='HTML'
            )
            return ConversationHandler.END
        
        # Formater et envoyer les résultats
        title = results[0].get('title', 'Dorks')
        snippet = results[0].get('snippet', '')
        
        header = f"🔎 <b>DORKS - {category.upper()}</b> 🔎\n\n"
        if domain:
            header += f"<b>Domaine cible:</b> <code>{domain}</code>\n\n"
        else:
            header += f"<b>Dorks génériques</b> (remplacez 'example.com' par votre cible)\n\n"
        
        header += f"<i>{DORKS_CATEGORIES.get(category, '')}</i>\n\n"
        header += "<b>Dorks prêts à utiliser:</b>\n\n"
        
        # Formater le snippet pour Telegram
        snippet_parts = snippet.split("\n\n")
        dorks_list = snippet_parts[1] if len(snippet_parts) > 1 else snippet
        
        # Limiter la longueur totale du message
        if len(header + dorks_list) > 4000:
            parts = []
            current_part = header
            for line in dorks_list.split('\n'):
                if len(current_part + line + '\n') > 4000:
                    parts.append(current_part)
                    current_part = line + '\n'
                else:
                    current_part += line + '\n'
            
            if current_part:
                parts.append(current_part)
            
            # Envoyer en plusieurs messages
            for i, part in enumerate(parts):
                if i == 0:  # Premier message avec header
                    await update.message.reply_text(part, parse_mode='HTML')
                else:  # Messages suivants
                    await update.message.reply_text(part, parse_mode='HTML')
        else:
            # Tout envoyer en un seul message
            await update.message.reply_text(header + dorks_list, parse_mode='HTML')
        
        # Ajouter un message pour expliquer comment utiliser ces dorks
        usage_text = (
            "<b>📝 COMMENT UTILISER CES DORKS</b>\n\n"
            "1. Copiez le dork qui vous intéresse\n"
            "2. Collez-le dans un moteur de recherche (Google, DuckDuckGo, etc.)\n"
            "3. Analysez les résultats pour identifier les vulnérabilités potentielles\n\n"
            "<b>⚠️ RAPPEL</b>: N'utilisez ces dorks que sur des domaines pour lesquels vous avez l'autorisation."
        )
        
        await update.message.reply_text(usage_text, parse_mode='HTML')
    except Exception as e:
        logger.error(f"Erreur lors de la génération des dorks: {str(e)}")
        await update.message.reply_text(
            f"❌ <b>ERREUR</b> ❌\n\n"
            f"Une erreur s'est produite lors de la génération des dorks:\n"
            f"<code>{str(e)}</code>",
            parse_mode='HTML'
        )
    
    return ConversationHandler.END

async def domain_input_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gère l'entrée du domaine"""
    domain = update.message.text.strip()
    
    # Validation basique du domaine
    domain_regex = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    if not re.match(domain_regex, domain, re.IGNORECASE):
        await update.message.reply_text(
            "⚠️ <b>FORMAT INVALIDE</b> ⚠️\n\n"
            "Le format du domaine n'est pas valide.\n"
            "Veuillez entrer un domaine au format correct (ex: example.com):",
            parse_mode='HTML'
        )
        return DOMAIN_INPUT
    
    await update.message.reply_text(
        f"🔄 <b>ANALYSE EN COURS</b> 🔄\n\n"
        f"Domaine cible: <code>{domain}</code>\n"
        f"• Récupération des informations WHOIS\n"
        f"• Analyse des enregistrements DNS\n"
        f"• Vérification des ports ouverts\n"
        f"• Recherche de menaces connues\n\n"
        f"Veuillez patienter...",
        parse_mode='HTML'
    )
    
    try:
        results = await scan_domain(domain)
        
        # Enregistrer les résultats pour la génération de rapport
        context.user_data['last_results'] = results
        context.user_data['last_type'] = 'domain'
        
        # Formater les résultats avec une meilleure présentation
        header = f"🔒 <b>RAPPORT DE SÉCURITÉ: {domain}</b> 🔒\n\n"
        
        # Ajouter un résumé rapide
        whois_data = next((r for r in results if r.get('title') == 'Informations WHOIS'), None)
        dns_data = next((r for r in results if r.get('title') == 'Enregistrements DNS'), None)
        vt_data = next((r for r in results if r.get('title') == 'Analyse VirusTotal'), None)
        ports_data = next((r for r in results if r.get('title') == 'Ports ouverts'), None)
        
        summary = "<b>📝 RÉSUMÉ RAPIDE:</b>\n"
        if whois_data:
            registrar = whois_data.get('details', {}).get('registrar', 'Non disponible')
            creation = whois_data.get('details', {}).get('creation_date', 'Non disponible')
            summary += f"• Registrar: <code>{registrar}</code>\n"
            summary += f"• Création: <code>{creation[:10] if len(creation) > 10 else creation}</code>\n"
        
        if dns_data:
            a_records = dns_data.get('details', {}).get('A', ['Non disponible'])
            summary += f"• Adresse IP: <code>{a_records[0] if a_records else 'Non disponible'}</code>\n"
        
        if vt_data:
            malicious = vt_data.get('details', {}).get('malicious', 0)
            summary += f"• Menaces détectées: <code>{malicious}</code>\n"
        
        if ports_data:
            open_ports = ports_data.get('details', {}).get('open_ports', [])
            if isinstance(open_ports, list) and open_ports:
                summary += f"• Ports ouverts: <code>{len(open_ports)}</code>\n"
        
        # Construire le message complet section par section
        sections = []
        
        # Parcourir chaque catégorie de résultats
        for result in results:
            section = f"<b>📌 {result['title']}</b> <i>({result['source']})</i>\n"
            
            if 'details' in result:
                for key, value in result['details'].items():
                    if isinstance(value, list):
                        section += f"  • <b>{key}</b>: <code>{', '.join(str(v) for v in value)}</code>\n"
                    else:
                        # Colorer certains résultats importants
                        if key == 'malicious' and int(value) > 0:
                            section += f"  • <b>{key}</b>: <code>⚠️ {value}</code>\n"
                        elif key == 'warning' or key == 'error':
                            section += f"  • <b>{key}</b>: <code>⚠️ {value}</code>\n"
                        else:
                            section += f"  • <b>{key}</b>: <code>{value}</code>\n"
            
            sections.append(section)
        
        footer = "\n<b>📊 ACTIONS POSSIBLES:</b>\n"
        footer += "• /rapport - Générer un PDF détaillé\n"
        footer += "• /scan - Lancer une autre analyse\n"
        footer += "• /recherche - Retour au menu principal"
        
        # Assembler le message final
        response = header + summary + "\n\n" + "\n\n".join(sections) + "\n" + footer
        
        # Envoyer les résultats
        if len(response) > 4096:
            # Premier message avec entête et résumé
            first_part = header + summary + "\n\n<i>Suite dans le prochain message...</i>"
            await update.message.reply_text(first_part, parse_mode='HTML')
            
            # Diviser le reste en morceaux
            remaining = "\n\n".join(sections) + "\n" + footer
            for i in range(0, len(remaining), 3800):
                part = remaining[i:i+3800]
                if i + 3800 >= len(remaining):
                    part += "\n" + footer
                await update.message.reply_text(part, parse_mode='HTML')
        else:
            await update.message.reply_text(response, parse_mode='HTML')
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse du domaine: {str(e)}")
        await update.message.reply_text(
            f"❌ <b>ERREUR D'ANALYSE</b> ❌\n\n"
            f"Une erreur s'est produite lors de l'analyse du domaine:\n"
            f"<code>{str(e)}</code>\n\n"
            f"Veuillez réessayer ou contacter l'administrateur.",
            parse_mode='HTML'
        )
    
    return ConversationHandler.END

async def url_input_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gère l'entrée de l'URL"""
    url = update.message.text.strip()
    
    # Validation basique de l'URL
    url_regex = r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(/[-\w%!$&\'()*+,;=:]*)*$'
    if not re.match(url_regex, url):
        await update.message.reply_text(
            "⚠️ <b>URL INVALIDE</b> ⚠️\n\n"
            "Le format de l'URL n'est pas valide.\n"
            "Veuillez entrer une URL complète commençant par http:// ou https:// (ex: https://example.com)",
            parse_mode='HTML'
        )
        return URL_INPUT
    
    # Afficher un message pendant l'analyse
    await update.message.reply_text(
        f"🔍 <b>ANALYSE DE SÉCURITÉ URL</b> 🔍\n\n"
        f"Cible: <code>{url}</code>\n\n"
        f"<b>Opérations en cours:</b>\n"
        f"• Vérification des en-têtes de sécurité\n"
        f"• Analyse des redirections\n"
        f"• Recherche de vulnérabilités\n"
        f"• Scan de réputation\n\n"
        f"<i>Cette opération peut prendre quelques instants...</i>",
        parse_mode='HTML'
    )
    
    try:
        results = await scan_url(url)
        
        # Enregistrer les résultats pour la génération de rapport
        context.user_data['last_results'] = results
        context.user_data['last_type'] = 'url'
        
        # Trouver les informations importantes pour le résumé
        headers_data = next((r for r in results if r.get('title') == 'En-têtes de sécurité'), None)
        security_check = next((r for r in results if r.get('title') == 'Évaluation de sécurité'), None)
        vt_data = next((r for r in results if r.get('title') == 'Analyse VirusTotal'), None)
        
        # Construire l'en-tête avec l'URL raccourcie pour l'affichage
        display_url = url
        if len(url) > 40:
            display_url = url[:37] + "..."
        
        header = f"🛡️ <b>ANALYSE DE SÉCURITÉ WEB</b> 🛡️\n"
        header += f"<b>URL:</b> <code>{display_url}</code>\n\n"
        
        # Créer un résumé visuel
        summary = "<b>📝 RÉSUMÉ DES RÉSULTATS:</b>\n"
        
        # Évaluation de sécurité
        security_score = "N/A"
        if security_check:
            security_score = security_check.get('details', {}).get('score', "N/A")
            recommendations = security_check.get('details', {}).get('recommandations', [])
            
            # Convertir le score en représentation visuelle
            if security_score != "N/A":
                score_rating = ""
                score_num = int(security_score.split('/')[0])
                if score_num == 4:
                    score_rating = "🟢 Excellent"
                elif score_num == 3:
                    score_rating = "🟢 Bon"
                elif score_num == 2:
                    score_rating = "🟡 Moyen"
                elif score_num == 1:
                    score_rating = "🔴 Faible"
                else:
                    score_rating = "🔴 Critique"
                
                summary += f"• <b>Score de sécurité:</b> {score_rating} ({security_score})\n"
            
            if recommendations and len(recommendations) > 0:
                summary += f"• <b>Problèmes détectés:</b> <code>{len(recommendations)}</code>\n"
        
        # VirusTotal 
        if vt_data:
            malicious = vt_data.get('details', {}).get('malicious', 0)
            if int(malicious) > 0:
                summary += f"• <b>Réputation:</b> 🔴 <code>{malicious} détections de menaces</code>\n"
            else:
                summary += f"• <b>Réputation:</b> 🟢 <code>Aucune menace détectée</code>\n"
        
        # Construire les sections détaillées
        sections = []
        
        # Section pour chaque résultat
        for result in results:
            section = f"<b>📌 {result['title']}</b> <i>({result['source']})</i>\n"
            
            if 'details' in result:
                for key, value in result['details'].items():
                    if key == 'recommandations' and isinstance(value, list):
                        section += f"  • <b>{key}:</b>\n"
                        for i, rec in enumerate(value, 1):
                            section += f"    {i}. <code>{rec}</code>\n"
                    elif isinstance(value, list):
                        section += f"  • <b>{key}:</b> <code>{', '.join(str(v) for v in value)}</code>\n"
                    else:
                        # Mise en forme spéciale pour certains en-têtes
                        if result['title'] == 'En-têtes de sécurité':
                            # Colorer les en-têtes selon leur présence
                            if key in ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options']:
                                if 'Non présent' in str(value):
                                    section += f"  • <b>{key}:</b> 🔴 <code>{value}</code>\n"
                                else:
                                    section += f"  • <b>{key}:</b> 🟢 <code>{value}</code>\n"
                            else:
                                section += f"  • <b>{key}:</b> <code>{value}</code>\n"
                        # Coloration pour les résultats de VirusTotal
                        elif key == 'malicious' and int(value) > 0:
                            section += f"  • <b>{key}:</b> 🔴 <code>{value}</code>\n"
                        elif key in ['suspicious', 'warning', 'error'] and value:
                            section += f"  • <b>{key}:</b> 🟡 <code>{value}</code>\n"
                        else:
                            section += f"  • <b>{key}:</b> <code>{value}</code>\n"
            
            sections.append(section)
        
        # Ajouter des suggestions basées sur les résultats
        footer = "\n<b>🔧 RECOMMANDATIONS:</b>\n"
        if security_check and 'details' in security_check and 'recommandations' in security_check['details']:
            recs = security_check['details']['recommandations']
            if recs and len(recs) > 0:
                footer += "<i>Pour améliorer la sécurité:</i>\n"
                for i, rec in enumerate(recs[:3], 1):  # Limiter à 3 recommandations pour la lisibilité
                    footer += f"{i}. {rec}\n"
                if len(recs) > 3:
                    footer += f"<i>+ {len(recs) - 3} autres recommandations dans le rapport détaillé</i>\n"
            else:
                footer += "✅ <i>Cette URL semble bien configurée pour la sécurité!</i>\n"
        
        footer += "\n<b>📊 ACTIONS POSSIBLES:</b>\n"
        footer += "• /rapport - Générer un PDF détaillé\n"
        footer += "• /scan - Analyser une autre cible\n"
        footer += "• /recherche - Retour au menu principal"
        
        # Assembler le message final
        response = header + summary + "\n\n" + "\n\n".join(sections) + "\n" + footer
        
        # Envoyer les résultats
        if len(response) > 4096:
            # Premier message avec entête et résumé
            first_part = header + summary + "\n\n<i>Suite dans le prochain message...</i>"
            await update.message.reply_text(first_part, parse_mode='HTML')
            
            # Diviser le reste en morceaux
            remaining = "\n\n".join(sections) + "\n" + footer
            for i in range(0, len(remaining), 3800):
                part = remaining[i:i+3800]
                if i + 3800 >= len(remaining):
                    part += "\n" + footer
                await update.message.reply_text(part, parse_mode='HTML')
        else:
            await update.message.reply_text(response, parse_mode='HTML')
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse de l'URL: {str(e)}")
        await update.message.reply_text(
            f"❌ <b>ERREUR D'ANALYSE</b> ❌\n\n"
            f"Une erreur s'est produite lors de l'analyse de l'URL:\n"
            f"<code>{str(e)}</code>\n\n"
            f"Veuillez vérifier que l'URL est accessible et réessayer.",
            parse_mode='HTML'
        )
    
    return ConversationHandler.END

async def email_input_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gère l'entrée de l'email"""
    email = update.message.text.strip()
    
    # Validation basique de l'email
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        await update.message.reply_text(
            "⚠️ <b>EMAIL INVALIDE</b> ⚠️\n\n"
            "Le format de l'adresse email n'est pas valide.\n"
            "Veuillez entrer une adresse au format correct (ex: utilisateur@domaine.com)",
            parse_mode='HTML'
        )
        return EMAIL_INPUT
    
    # Extraire le domaine pour l'affichage
    domain = email.split('@')[1]
    
    await update.message.reply_text(
        f"✉️ <b>ANALYSE EMAIL EN COURS</b> ✉️\n\n"
        f"Adresse: <code>{email}</code>\n"
        f"Domaine: <code>{domain}</code>\n\n"
        f"<b>Vérifications en cours:</b>\n"
        f"• Format et syntaxe\n"
        f"• Configuration du domaine\n"
        f"• Enregistrements MX\n"
        f"• Protection SPF/DMARC\n\n"
        f"<i>Veuillez patienter pendant l'analyse...</i>",
        parse_mode='HTML'
    )
    
    try:
        results = await scan_email(email)
        
        # Enregistrer les résultats pour la génération de rapport
        context.user_data['last_results'] = results
        context.user_data['last_type'] = 'email'
        
        # Trouver les informations importantes pour l'affichage
        format_check = next((r for r in results if r.get('title') == 'Validation du format'), None)
        domain_check = next((r for r in results if r.get('title') == 'Validation du domaine'), None)
        mx_check = next((r for r in results if r.get('title') == 'Enregistrements MX'), None)
        spf_check = next((r for r in results if r.get('title') == 'Enregistrement SPF'), None)
        dmarc_check = next((r for r in results if r.get('title') == 'Enregistrement DMARC'), None)
        
        # Construire l'en-tête
        header = f"✉️ <b>RAPPORT D'ANALYSE EMAIL</b> ✉️\n"
        header += f"<b>Adresse:</b> <code>{email}</code>\n\n"
        
        # Créer un résumé de sécurité
        summary = "<b>📝 RÉSUMÉ DE SÉCURITÉ:</b>\n"
        
        # Vérifier si le domaine peut recevoir des emails
        domain_status = "⚠️ Problèmes détectés"
        if domain_check:
            status = domain_check.get('details', {}).get('status', '')
            if 'peut recevoir' in status:
                domain_status = "✅ Fonctionnel"
        summary += f"• <b>Réception d'emails:</b> {domain_status}\n"
        
        # Vérifier SPF
        spf_status = "❌ Non configuré"
        if spf_check:
            if 'warning' not in spf_check.get('details', {}):
                spf_status = "✅ Configuré"
        summary += f"• <b>Protection SPF:</b> {spf_status}\n"
        
        # Vérifier DMARC
        dmarc_status = "❌ Non configuré"
        if dmarc_check:
            if 'warning' not in dmarc_check.get('details', {}):
                dmarc_status = "✅ Configuré"
        summary += f"• <b>Protection DMARC:</b> {dmarc_status}\n"
        
        # Indicateur de sécurité global
        security_level = "🔴 Faible"
        if spf_status == "✅ Configuré" and dmarc_status == "✅ Configuré":
            security_level = "🟢 Élevé"
        elif spf_status == "✅ Configuré" or dmarc_status == "✅ Configuré":
            security_level = "🟡 Moyen"
        summary += f"• <b>Niveau de sécurité:</b> {security_level}\n"
        
        # Construire les sections détaillées
        sections = []
        
        # Ajouter chaque section de résultat avec une mise en forme améliorée
        for result in results:
            section = f"<b>📌 {result['title']}</b> <i>({result['source']})</i>\n"
            
            if 'details' in result:
                for key, value in result['details'].items():
                    if isinstance(value, list):
                        section += f"  • <b>{key}:</b> <code>{', '.join(str(v) for v in value)}</code>\n"
                    else:
                        # Coloration spécifique pour les statuts
                        if 'warning' in key or 'error' in key:
                            section += f"  • <b>{key}:</b> 🔴 <code>{value}</code>\n"
                        elif 'status' in key and 'peut recevoir' in str(value):
                            section += f"  • <b>{key}:</b> 🟢 <code>{value}</code>\n"
                        elif key == 'spf_record' or key == 'dmarc_record':
                            section += f"  • <b>{key}:</b> 🟢 <code>{value}</code>\n"
                        elif 'info' in key:
                            section += f"  • <b>{key}:</b> ℹ️ <code>{value}</code>\n"
                        else:
                            section += f"  • <b>{key}:</b> <code>{value}</code>\n"
            
            sections.append(section)
        
        # Ajouter des recommandations basées sur les résultats
        footer = "\n<b>🔧 RECOMMANDATIONS:</b>\n"
        
        if spf_status == "❌ Non configuré":
            footer += "• Configurez un enregistrement SPF pour ce domaine\n"
        
        if dmarc_status == "❌ Non configuré":
            footer += "• Ajoutez un enregistrement DMARC pour améliorer la sécurité\n"
        
        if spf_status == "✅ Configuré" and dmarc_status == "✅ Configuré":
            footer += "• Excellent! Ce domaine est bien protégé contre l'usurpation d'identité\n"
        
        footer += "\n<b>📊 ACTIONS POSSIBLES:</b>\n"
        footer += "• /rapport - Générer un PDF détaillé\n"
        footer += "• /scan - Analyser une autre cible\n"
        footer += "• /recherche - Retour au menu principal"
        
        # Assembler le message final
        response = header + summary + "\n\n" + "\n\n".join(sections) + "\n" + footer
        
        # Envoyer les résultats
        if len(response) > 4096:
            # Premier message avec entête et résumé
            first_part = header + summary + "\n\n<i>Suite dans le prochain message...</i>"
            await update.message.reply_text(first_part, parse_mode='HTML')
            
            # Diviser le reste en morceaux
            remaining = "\n\n".join(sections) + "\n" + footer
            for i in range(0, len(remaining), 3800):
                part = remaining[i:i+3800]
                if i + 3800 >= len(remaining):
                    part += "\n" + footer
                await update.message.reply_text(part, parse_mode='HTML')
        else:
            await update.message.reply_text(response, parse_mode='HTML')
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse de l'email: {str(e)}")
        await update.message.reply_text(
            f"❌ <b>ERREUR D'ANALYSE</b> ❌\n\n"
            f"Une erreur s'est produite lors de l'analyse de l'email:\n"
            f"<code>{str(e)}</code>\n\n"
            f"Veuillez vérifier que le domaine existe et réessayer.",
            parse_mode='HTML'
        )
    
    return ConversationHandler.END

async def keyword_input_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gère l'entrée du mot-clé de recherche"""
    keyword = update.message.text.strip()
    search_type = context.user_data.get('search_type', 'web')
    
    # Messages personnalisés selon le type de recherche
    search_icons = {
        'web': '🌐',
        'reddit': '📱',
        'github': '💻'
    }
    
    search_names = {
        'web': 'Web',
        'reddit': 'Reddit',
        'github': 'GitHub'
    }
    
    icon = search_icons.get(search_type, '🔍')
    name = search_names.get(search_type, 'Inconnu')
    
    await update.message.reply_text(
        f"{icon} <b>RECHERCHE {name.upper()}</b> {icon}\n\n"
        f"Requête: <code>{keyword}</code>\n"
        f"<i>Recherche en cours, veuillez patienter...</i>",
        parse_mode='HTML'
    )
    
    try:
        if search_type == 'web':
            results = await search_web(keyword)
        elif search_type == 'reddit':
            results = await search_reddit(keyword)
        elif search_type == 'github':
            results = await search_github(keyword)
        else:
            results = [{'title': 'Erreur', 'snippet': "Type de recherche non reconnu", 'source': 'Error'}]
        
        # Enregistrer les résultats pour la génération de rapport
        context.user_data['last_results'] = results
        context.user_data['last_type'] = 'search'
        
        # En-tête avec des détails sur la recherche
        header = f"{icon} <b>RÉSULTATS DE RECHERCHE {name.upper()}</b> {icon}\n\n"
        header += f"<b>Requête:</b> <code>{keyword}</code>\n"
        header += f"<b>Résultats trouvés:</b> <code>{len(results)}</code>\n\n"
        
        # Formater les résultats avec HTML pour une meilleure présentation
        result_sections = []
        
        for idx, result in enumerate(results, 1):
            title = result.get('title', 'Sans titre')
            source = result.get('source', 'Source inconnue')
            url = result.get('url', '')
            snippet = result.get('snippet', 'Pas de description disponible')
            
            # Coloration spéciale pour les sources
            source_colored = source
            if 'Error' in source:
                source_colored = f"⚠️ {source}"
            
            section = f"<b>{idx}. {title}</b>\n"
            section += f"<i>Source: {source_colored}</i>\n"
            
            if url:
                # Formater les URLs longues
                display_url = url
                if len(url) > 40:
                    display_url = url[:37] + "..."
                section += f"🔗 <code>{display_url}</code>\n"
            
            # Formater le snippet
            if snippet:
                # Limiter la longueur du snippet pour l'affichage
                if len(snippet) > 200:
                    snippet = snippet[:197] + "..."
                section += f"{snippet}\n"
            
            result_sections.append(section)
        
        # Ajouter des astuces ou des suggestions basées sur le type de recherche
        footer = "\n<b>📌 ASTUCES:</b>\n"
        
        if search_type == 'web':
            footer += "• Essayez d'utiliser des mots-clés plus spécifiques pour affiner vos résultats\n"
            footer += "• Utilisez des guillemets pour rechercher une expression exacte\n"
        elif search_type == 'reddit':
            footer += "• Préfixez votre recherche avec 'subreddit:' pour cibler un subreddit spécifique\n"
            footer += "• Utilisez 'author:' pour trouver les publications d'un utilisateur spécifique\n"
        elif search_type == 'github':
            footer += "• Ajoutez 'language:python' (ou autre langage) pour filtrer par type de code\n"
            footer += "• Utilisez 'stars:>100' pour trouver des dépôts populaires\n"
        
        footer += "\n<b>📊 ACTIONS POSSIBLES:</b>\n"
        footer += "• /rapport - Générer un PDF de ces résultats\n"
        footer += "• /recherche - Effectuer une nouvelle recherche\n"
        footer += "• /scan - Analyser un élément spécifique"
        
        # Assembler le message final
        response = header + "\n".join(result_sections) + "\n" + footer
        
        # Envoyer les résultats
        if len(response) > 4096:
            # Premier message avec l'en-tête
            first_part = header + "<i>Les résultats suivent dans plusieurs messages...</i>"
            await update.message.reply_text(first_part, parse_mode='HTML')
            
            # Diviser les résultats en morceaux
            chunks = []
            current_chunk = ""
            
            for section in result_sections:
                if len(current_chunk) + len(section) > 3800:
                    chunks.append(current_chunk)
                    current_chunk = section + "\n"
                else:
                    current_chunk += section + "\n"
            
            if current_chunk:
                chunks.append(current_chunk)
            
            # Envoyer les morceaux
            for i, chunk in enumerate(chunks):
                if i == len(chunks) - 1:
                    # Dernier morceau avec le footer
                    await update.message.reply_text(chunk + footer, parse_mode='HTML')
                else:
                    await update.message.reply_text(chunk, parse_mode='HTML')
        else:
            await update.message.reply_text(response, parse_mode='HTML')
    except Exception as e:
        logger.error(f"Erreur lors de la recherche: {str(e)}")
        await update.message.reply_text(
            f"❌ <b>ERREUR DE RECHERCHE</b> ❌\n\n"
            f"Une erreur s'est produite lors de la recherche {name}:\n"
            f"<code>{str(e)}</code>\n\n"
            f"Veuillez réessayer avec d'autres termes ou options.",
            parse_mode='HTML'
        )
    
    return ConversationHandler.END

async def dork_input_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gère l'entrée du dork personnalisé"""
    dork = update.message.text.strip()
    
    await update.message.reply_text(
        f"🔎 <b>ANALYSE DE DORK</b> 🔎\n\n"
        f"Requête: <code>{dork}</code>\n"
        f"<i>Analyse en cours, veuillez patienter...</i>",
        parse_mode='HTML'
    )
    
    try:
        # Extraire le domaine si présent dans le dork
        domain = None
        if "site:" in dork:
            domain_match = re.search(r'site:([^\s]+)', dork)
            if domain_match:
                domain = domain_match.group(1)
        
        # Appel à la fonction search_google_dorks avec le domaine s'il a été extrait
        results = await search_google_dorks(dork, target_domain=domain)
        
        # Enregistrer les résultats pour la génération de rapport
        context.user_data['last_results'] = results
        context.user_data['last_type'] = 'search'
        
        # En-tête détaillé
        header = f"🔎 <b>ANALYSE DE DORK</b> 🔎\n\n"
        header += f"<b>Dork analysé:</b> <code>{dork}</code>\n\n"
        
        # Formatage de la réponse en tenant compte des limitations de Telegram
        response_parts = []
        current_part = header
        
        for result in results:
            title = result.get('title', 'Sans titre')
            source = result.get('source', 'Source inconnue')
            snippet = result.get('snippet', 'Pas d\'information disponible')
            
            # Création d'une section pour ce résultat
            section = f"<b>📌 {title}</b> <i>({source})</i>\n"
            section += f"{snippet}\n\n"
            
            # Vérifier si l'ajout de cette section va dépasser la limite de 4096 caractères
            if len(current_part) + len(section) > 3800:  # Marge de sécurité
                response_parts.append(current_part)
                current_part = section
            else:
                current_part += section
        
        # Ajouter la dernière partie s'il en reste
        if current_part:
            response_parts.append(current_part)
        
        # Envoyer les messages en plusieurs parties si nécessaire
        for i, part in enumerate(response_parts):
            if i == len(response_parts) - 1:
                # Ajouter un pied de page uniquement au dernier message
                footer = "\n<b>📊 ACTIONS POSSIBLES:</b>\n"
                footer += "• /rapport - Générer un PDF de ces résultats\n"
                footer += "• /recherche - Effectuer une nouvelle recherche\n"
                footer += "• /scan - Analyser plus en profondeur"
                
                if len(part) + len(footer) <= 4096:
                    part += footer
                else:
                    await update.message.reply_text(part, parse_mode='HTML')
                    await update.message.reply_text(footer, parse_mode='HTML')
                    continue
            
            await update.message.reply_text(part, parse_mode='HTML')
    
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse du dork: {str(e)}")
        await update.message.reply_text(
            f"❌ <b>ERREUR D'ANALYSE</b> ❌\n\n"
            f"Une erreur s'est produite lors de l'analyse du dork:\n"
            f"<code>{str(e)}</code>\n\n"
            f"Veuillez vérifier la syntaxe et réessayer.",
            parse_mode='HTML'
        )
    
    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Annule et termine la conversation"""
    await update.message.reply_text(
        "❌ <b>OPÉRATION ANNULÉE</b> ❌\n\n"
        "Que souhaitez-vous faire maintenant?\n\n"
        "🔍 /recherche - Explorer des informations\n"
        "🛡️ /scan - Analyser la sécurité\n"
        "📊 /rapport - Générer un rapport\n"
        "ℹ️ /aide - Voir les instructions",
        parse_mode='HTML'
    )
    return ConversationHandler.END

def main():
    """Fonction principale pour démarrer le bot"""
    # Vérifier si le token du bot est configuré
    if TELEGRAM_BOT_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN":
        print("Veuillez configurer votre token de bot Telegram dans config.py ou via les variables d'environnement!")
        return
    
    # Créer l'application
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    # Conversation handler pour la recherche
    search_conv_handler = ConversationHandler(
        entry_points=[CommandHandler("recherche", search_command)],
        states={
            CHOOSE_SEARCH: [CallbackQueryHandler(button_handler)],
            CHOOSE_DORK_CATEGORY: [CallbackQueryHandler(button_handler)],
            DORK_DOMAIN_INPUT: [MessageHandler(filters.TEXT & ~filters.COMMAND, dork_domain_input_handler)],
            KEYWORD_INPUT: [MessageHandler(filters.TEXT & ~filters.COMMAND, keyword_input_handler)],
            DORK_INPUT: [MessageHandler(filters.TEXT & ~filters.COMMAND, dork_input_handler)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    
    # Conversation handler pour le scan
    scan_conv_handler = ConversationHandler(
        entry_points=[CommandHandler("scan", scan_command)],
        states={
            CHOOSE_SCAN: [CallbackQueryHandler(button_handler)],
            DOMAIN_INPUT: [MessageHandler(filters.TEXT & ~filters.COMMAND, domain_input_handler)],
            URL_INPUT: [MessageHandler(filters.TEXT & ~filters.COMMAND, url_input_handler)],
            EMAIL_INPUT: [MessageHandler(filters.TEXT & ~filters.COMMAND, email_input_handler)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    
    # Ajouter les handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("aide", help_command))
    application.add_handler(CommandHandler("rapport", report_command))
    application.add_handler(search_conv_handler)
    application.add_handler(scan_conv_handler)
    
    # Démarrer le bot
    print("🚀 Bot de Sécurité et Recherche démarré! 🛡️")
    print("📋 Commandes disponibles: /start, /recherche, /scan, /rapport, /aide")
    print("📊 Prêt à recevoir des demandes...")
    application.run_polling()

if __name__ == "__main__":
    main()