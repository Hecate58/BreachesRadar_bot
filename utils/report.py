import logging
from datetime import datetime
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

logger = logging.getLogger(__name__)

async def generate_pdf_report(data, report_type):
    """Génère un rapport PDF basé sur les données collectées"""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Créer un style personnalisé pour les titres
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=16,
        spaceAfter=12
    )
    
    subtitle_style = ParagraphStyle(
        'CustomSubTitle',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=10
    )
    
    normal_style = styles["Normal"]
    normal_style.fontSize = 10
    
    # Éléments du document
    elements = []
    
    # Titre principal et logo
    if report_type == 'search':
        title = "Rapport de Recherche"
    elif report_type == 'domain':
        title = "Rapport d'Analyse de Domaine"
    elif report_type == 'url':
        title = "Rapport d'Analyse d'URL"
    elif report_type == 'email':
        title = "Rapport d'Analyse d'Email"
    else:
        title = "Rapport de Sécurité"
    
    # Ajouter le titre et la date
    elements.append(Paragraph(title, title_style))
    elements.append(Spacer(1, 12))
    
    # Date du rapport
    date_string = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    elements.append(Paragraph(f"Rapport généré le: {date_string}", normal_style))
    elements.append(Spacer(1, 20))
    
    # Résumé du rapport
    summary_style = ParagraphStyle(
        'Summary',
        parent=styles['Normal'],
        fontSize=11,
        leading=14,
        spaceAfter=12,
        borderWidth=1,
        borderColor=colors.grey,
        borderPadding=10,
        borderRadius=5,
        backColor=colors.lightgrey
    )
    
    summary_text = "Ce rapport a été généré automatiquement par le Bot de Sécurité. "
    
    if report_type == 'search':
        summary_text += "Il contient les résultats de votre recherche. Les informations présentées proviennent de diverses sources et peuvent nécessiter une vérification supplémentaire."
    elif report_type == 'domain':
        summary_text += "Il contient une analyse de sécurité du domaine spécifié, incluant des informations DNS, WHOIS et une vérification des vulnérabilités connues."
    elif report_type == 'url':
        summary_text += "Il contient une analyse de sécurité de l'URL spécifiée, incluant les en-têtes de sécurité et les résultats d'analyse des services de réputation."
    elif report_type == 'email':
        summary_text += "Il contient une analyse de l'adresse email spécifiée, incluant la validation du domaine et les configurations de sécurité associées."
    
    elements.append(Paragraph(summary_text, summary_style))
    elements.append(Spacer(1, 20))
    
    # Table des matières simple
    toc_items = []
    for i, result in enumerate(data, 1):
        toc_items.append(f"{i}. {result.get('title', 'Sans titre')}")
    
    toc_text = "Table des matières:\n" + "\n".join(toc_items)
    elements.append(Paragraph(toc_text, normal_style))
    elements.append(Spacer(1, 20))
    
    # Ajouter les données
    if report_type == 'search':
        # Rapport de recherche
        for i, result in enumerate(data, 1):
            elements.append(Paragraph(f"{i}. {result.get('title', 'Sans titre')}", subtitle_style))
            elements.append(Paragraph(f"Source: {result.get('source', 'Inconnue')}", normal_style))
            if 'url' in result and result['url']:
                elements.append(Paragraph(f"URL: {result['url']}", normal_style))
            elements.append(Paragraph(result.get('snippet', 'Pas de description'), normal_style))
            elements.append(Spacer(1, 10))
    else:
        # Rapports de scan
        for i, result in enumerate(data, 1):
            elements.append(Paragraph(f"{i}. {result.get('title', 'Sans titre')}", subtitle_style))
            elements.append(Paragraph(f"Source: {result.get('source', 'Inconnue')}", normal_style))
            
            if 'details' in result:
                details = result['details']
                
                # Convertir les détails en tableau
                table_data = []
                table_data.append(["Attribut", "Valeur"])  # En-têtes
                
                for key, value in details.items():
                    if isinstance(value, list):
                        value = ", ".join(value)
                    table_data.append([key, str(value)])
                
                if len(table_data) > 1:  # S'assurer qu'il y a des données en plus des en-têtes
                    table = Table(table_data, colWidths=[150, 350])
                    table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (1, 0), colors.lightgrey),
                        ('TEXTCOLOR', (0, 0), (1, 0), colors.black),
                        ('ALIGN', (0, 0), (1, 0), 'CENTER'),
                        ('FONT', (0, 0), (1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (1, 0), 8),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                        ('FONT', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 1), (-1, -1), 9),
                        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                        ('GRID', (0, 0), (-1, -1), 1, colors.grey)
                    ]))
                    elements.append(table)
            
            elements.append(Spacer(1, 15))
    
    # Notes de bas de page
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.grey
    )
    
    footer_text = "Note: Ce rapport est fourni à titre informatif uniquement. "
    footer_text += "Les résultats présentés peuvent nécessiter une vérification supplémentaire par un professionnel de la sécurité."
    
    elements.append(Spacer(1, 30))
    elements.append(Paragraph(footer_text, footer_style))
    
    # Construire le document
    try:
        doc.build(elements)
        
        # Récupérer le PDF du buffer
        buffer.seek(0)
        return buffer
    except Exception as e:
        logger.error(f"Erreur lors de la génération du PDF: {str(e)}")
        raise