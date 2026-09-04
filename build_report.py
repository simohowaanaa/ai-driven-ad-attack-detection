from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.enum.style import WD_STYLE_TYPE
from pathlib import Path
import shutil

ROOT = Path(r"C:\Users\simoh\Desktop\Dataprotect")
TEMPLATE = Path(r"C:\Users\simoh\Downloads\TemplateRapprtStage_4IIR.docx")
OUT = ROOT / "rapports" / "Rapport_PFA_Dataprotect_Detection_AD.docx"
OUT.parent.mkdir(parents=True, exist_ok=True)

NAVY = "17365D"
BLUE = "2E74B5"
PALE = "EAF1F8"
LIGHT = "F4F7FA"
GRAY = "5B6573"
GREEN = "1F6B45"
GOLD = "8A5A00"
RED = "9B1C1C"

def set_cell_shading(cell, fill):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = tcPr.find(qn('w:shd'))
    if shd is None:
        shd = OxmlElement('w:shd'); tcPr.append(shd)
    shd.set(qn('w:fill'), fill)

def set_cell_margins(cell, top=90, start=120, bottom=90, end=120):
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    tcMar = tcPr.first_child_found_in('w:tcMar')
    if tcMar is None:
        tcMar = OxmlElement('w:tcMar'); tcPr.append(tcMar)
    for m, val in [('top', top), ('start', start), ('bottom', bottom), ('end', end)]:
        node = tcMar.find(qn(f'w:{m}'))
        if node is None:
            node = OxmlElement(f'w:{m}'); tcMar.append(node)
        node.set(qn('w:w'), str(val)); node.set(qn('w:type'), 'dxa')

def set_repeat_table_header(row):
    trPr = row._tr.get_or_add_trPr()
    tblHeader = OxmlElement('w:tblHeader'); tblHeader.set(qn('w:val'), 'true'); trPr.append(tblHeader)

def set_table_widths(table, widths):
    for row in table.rows:
        for idx, w in enumerate(widths):
            row.cells[idx].width = Inches(w)
            tcPr = row.cells[idx]._tc.get_or_add_tcPr()
            tcW = tcPr.find(qn('w:tcW'))
            if tcW is None:
                tcW = OxmlElement('w:tcW'); tcPr.append(tcW)
            tcW.set(qn('w:w'), str(int(w*1440))); tcW.set(qn('w:type'), 'dxa')

def set_run(run, size=10.5, bold=False, color="000000", italic=False, font='Calibri'):
    run.font.name = font
    run._element.rPr.rFonts.set(qn('w:ascii'), font)
    run._element.rPr.rFonts.set(qn('w:hAnsi'), font)
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.italic = italic
    run.font.color.rgb = RGBColor.from_string(color)

def clear_doc(doc):
    body = doc._element.body
    sectPr = body.sectPr
    for child in list(body):
        if child is not sectPr:
            body.remove(child)

def add_numbering_definition(doc, bullet=False):
    """Create a native Word numbering definition and return its numId."""
    numbering = doc.part.numbering_part.element
    ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
    existing_abs = [int(x.get(qn('w:abstractNumId'))) for x in numbering.findall('w:abstractNum', ns) if x.get(qn('w:abstractNumId'))]
    existing_num = [int(x.get(qn('w:numId'))) for x in numbering.findall('w:num', ns) if x.get(qn('w:numId'))]
    abs_id = max(existing_abs, default=0) + 1
    num_id = max(existing_num, default=0) + 1
    abstract = OxmlElement('w:abstractNum'); abstract.set(qn('w:abstractNumId'), str(abs_id))
    lvl = OxmlElement('w:lvl'); lvl.set(qn('w:ilvl'), '0')
    start = OxmlElement('w:start'); start.set(qn('w:val'), '1'); lvl.append(start)
    fmt = OxmlElement('w:numFmt'); fmt.set(qn('w:val'), 'bullet' if bullet else 'decimal'); lvl.append(fmt)
    lvl_text = OxmlElement('w:lvlText'); lvl_text.set(qn('w:val'), '•' if bullet else '%1.'); lvl.append(lvl_text)
    jc = OxmlElement('w:lvlJc'); jc.set(qn('w:val'), 'left'); lvl.append(jc)
    pPr = OxmlElement('w:pPr')
    ind = OxmlElement('w:ind'); ind.set(qn('w:left'), '720'); ind.set(qn('w:hanging'), '360'); pPr.append(ind)
    lvl.append(pPr); abstract.append(lvl); numbering.append(abstract)
    num = OxmlElement('w:num'); num.set(qn('w:numId'), str(num_id))
    ref = OxmlElement('w:abstractNumId'); ref.set(qn('w:val'), str(abs_id)); num.append(ref); numbering.append(num)
    return num_id

def set_numbering(p, num_id):
    pPr = p._p.get_or_add_pPr()
    numPr = OxmlElement('w:numPr')
    ilvl = OxmlElement('w:ilvl'); ilvl.set(qn('w:val'), '0'); numPr.append(ilvl)
    nid = OxmlElement('w:numId'); nid.set(qn('w:val'), str(num_id)); numPr.append(nid)
    pPr.append(numPr)

def add_page_number(paragraph):
    paragraph.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    run = paragraph.add_run('Page ')
    set_run(run, size=8.5, color=GRAY)
    fld = OxmlElement('w:fldSimple'); fld.set(qn('w:instr'), 'PAGE')
    paragraph._p.append(fld)

def add_header_footer(section):
    header = section.header
    p = header.paragraphs[0]
    p.text = ''
    p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    r = p.add_run('PFA | Détection des attaques Active Directory')
    set_run(r, size=8.5, color=GRAY)
    footer = section.footer
    p = footer.paragraphs[0]
    p.text = ''
    add_page_number(p)

def add_title(doc, text, subtitle=None):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(52)
    p.paragraph_format.space_after = Pt(10)
    r = p.add_run(text)
    set_run(r, size=26, bold=True, color=NAVY)
    if subtitle:
        p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_after = Pt(28)
        r = p.add_run(subtitle); set_run(r, size=14, color=GRAY, italic=True)

def add_kicker(doc, text):
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(8); p.paragraph_format.space_after = Pt(8)
    r = p.add_run(text.upper()); set_run(r, size=10, bold=True, color=BLUE)

def add_heading(doc, text, level=1):
    p = doc.add_paragraph(style=f'Heading {level}')
    p.paragraph_format.keep_with_next = True
    p.add_run(text)
    return p

def add_text(doc, text, bold_lead=None):
    p = doc.add_paragraph(style='Normal')
    p.paragraph_format.space_after = Pt(7)
    p.paragraph_format.line_spacing = 1.22
    if bold_lead and text.startswith(bold_lead):
        r = p.add_run(bold_lead); set_run(r, bold=True)
        r = p.add_run(text[len(bold_lead):]); set_run(r)
    else:
        r = p.add_run(text); set_run(r)
    return p

def add_bullets(doc, items):
    for item in items:
        p = doc.add_paragraph()
        set_numbering(p, doc._bullet_num_id)
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.line_spacing = 1.15
        r = p.add_run(item); set_run(r)

def add_numbered(doc, items):
    for item in items:
        p = doc.add_paragraph()
        set_numbering(p, doc._decimal_num_id)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.line_spacing = 1.15
        r = p.add_run(item); set_run(r)

def add_callout(doc, label, text, color=PALE):
    t = doc.add_table(rows=1, cols=1)
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    t.autofit = False; set_table_widths(t,[6.3])
    c=t.cell(0,0); set_cell_shading(c,color); set_cell_margins(c,120,160,120,160)
    p=c.paragraphs[0]; p.paragraph_format.space_after=Pt(2)
    r=p.add_run(label+'  '); set_run(r,size=10.5,bold=True,color=NAVY)
    r=p.add_run(text); set_run(r,size=10.5,color='243447')
    doc.add_paragraph().paragraph_format.space_after=Pt(2)

def add_table(doc, headers, rows, widths=None, font_size=9):
    table = doc.add_table(rows=1, cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.style = 'Table Grid'; table.autofit=False
    if widths: set_table_widths(table,widths)
    hdr = table.rows[0]; set_repeat_table_header(hdr)
    for i,h in enumerate(headers):
        c=hdr.cells[i]; set_cell_shading(c,NAVY); set_cell_margins(c)
        c.vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER
        p=c.paragraphs[0]; p.paragraph_format.space_after=Pt(0)
        r=p.add_run(h); set_run(r,size=font_size,bold=True,color='FFFFFF')
    for row in rows:
        cells=table.add_row().cells
        for i,val in enumerate(row):
            c=cells[i]; set_cell_margins(c)
            if len(table.rows)%2==1: set_cell_shading(c,LIGHT)
            p=c.paragraphs[0]; p.paragraph_format.space_after=Pt(0)
            r=p.add_run(str(val)); set_run(r,size=font_size)
    doc.add_paragraph().paragraph_format.space_after=Pt(3)
    return table

def add_caption(doc, text):
    p=doc.add_paragraph(); p.alignment=WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after=Pt(8)
    r=p.add_run(text); set_run(r,size=8.5,italic=True,color=GRAY)

def add_toc_field(doc):
    p=doc.add_paragraph(); p.alignment=WD_ALIGN_PARAGRAPH.LEFT
    fld=OxmlElement('w:fldSimple'); fld.set(qn('w:instr'),'TOC \\o "1-3" \\h \\z \\u')
    p._p.append(fld)
    add_text(doc, 'Ouvrez ce document dans Microsoft Word puis mettez à jour le sommaire (clic droit > Mettre à jour les champs) afin de générer la pagination finale.')

def configure_styles(doc):
    normal=doc.styles['Normal']; normal.font.name='Calibri'; normal._element.rPr.rFonts.set(qn('w:ascii'),'Calibri'); normal._element.rPr.rFonts.set(qn('w:hAnsi'),'Calibri'); normal.font.size=Pt(10.5)
    normal.paragraph_format.space_after=Pt(7); normal.paragraph_format.line_spacing=1.22
    for name,size,color,before,after in [('Heading 1',16,BLUE,18,8),('Heading 2',13,BLUE,12,6),('Heading 3',11.5,NAVY,9,4)]:
        st=doc.styles[name]; st.font.name='Calibri'; st._element.rPr.rFonts.set(qn('w:ascii'),'Calibri'); st._element.rPr.rFonts.set(qn('w:hAnsi'),'Calibri'); st.font.size=Pt(size); st.font.bold=True; st.font.color.rgb=RGBColor.from_string(color); st.paragraph_format.space_before=Pt(before); st.paragraph_format.space_after=Pt(after); st.paragraph_format.keep_with_next=True

def cover(doc):
    add_kicker(doc,'École Marocaine des Sciences de l’Ingénieur — Filière Ingénierie Informatique et Réseaux')
    add_title(doc,'Rapport de Projet de Fin d’Études','Conception d’une plateforme de détection des attaques Active Directory par SIEM Wazuh et intelligence artificielle')
    add_callout(doc,'PROJET', 'Analyse, simulation et détection de 12 attaques Active Directory dans un laboratoire GOAD-Light isolé.',PALE)
    doc.add_paragraph().paragraph_format.space_after=Pt(12)
    add_table(doc,['Information','Détail'],[
        ['Organisme d’accueil','Dataprotect — Business Unit Security Intelligence / SOC'],
        ['Encadrant professionnel','Benkirane Abbes'],
        ['Établissement','École Marocaine des Sciences de l’Ingénieur (EMSI)'],
        ['Filière','Ingénierie Informatique et Réseaux (IIR)'],
        ['Réalisé par','[Nom et prénom de l’étudiant / des étudiants]'],
        ['Année universitaire','2025–2026'],
    ],[2.0,4.3],10)
    p=doc.add_paragraph(); p.alignment=WD_ALIGN_PARAGRAPH.CENTER; p.paragraph_format.space_before=Pt(26)
    r=p.add_run('Tanger — Août 2026'); set_run(r,size=11,bold=True,color=NAVY)
    doc.add_page_break()

def front_matter(doc):
    add_heading(doc,'Dédicace',1)
    add_text(doc,'À nos familles, pour leur soutien constant ; à nos enseignants, pour la qualité de leur accompagnement ; et à toutes les personnes qui contribuent à rendre les systèmes d’information plus sûrs.')
    doc.add_page_break()
    add_heading(doc,'Remerciements',1)
    add_text(doc,'Nous adressons nos sincères remerciements à l’équipe Dataprotect, et particulièrement à notre encadrant professionnel, pour son accompagnement, ses orientations techniques et la confiance accordée tout au long de ce projet. Nous remercions également les équipes pédagogiques de l’EMSI pour les connaissances et le cadre méthodologique qui ont rendu cette réalisation possible.')
    add_text(doc,'Ce travail a été réalisé exclusivement dans un laboratoire isolé et conçu à des fins pédagogiques. Les démonstrations reproduisent des techniques connues afin de mieux comprendre leurs traces et de construire des moyens de détection défensifs.')
    doc.add_page_break()
    add_heading(doc,'Résumé',1)
    add_text(doc,'Les environnements Active Directory concentrent les identités, les droits et les services critiques d’une organisation. Ils sont par conséquent une cible prioritaire des attaquants. Ce projet propose une démarche complète de détection : documenter les techniques offensives, construire un laboratoire isolé, simuler des attaques représentatives, centraliser les journaux avec Wazuh, compléter les angles morts par des règles sur mesure, puis appliquer une détection comportementale fondée sur l’apprentissage automatique.')
    add_text(doc,'Le laboratoire GOAD-Light déployé sur Azure comporte deux contrôleurs de domaine, un serveur MSSQL et une plateforme Wazuh. Douze attaques ont été rejouées ; sept règles Wazuh personnalisées ont ensuite été validées en conditions de laboratoire. Enfin, un modèle Isolation Forest a analysé les alertes collectées et a mis en évidence quatre comportements anormaux, dont des scénarios de Pass-the-Hash, de Golden Ticket et d’exécution de commandes via MSSQL.')
    add_text(doc,'Mots-clés : Active Directory, SOC, Wazuh, SIEM, détection d’anomalies, Isolation Forest, MITRE ATT&CK, Kerberos.')
    add_heading(doc,'Abstract',1)
    add_text(doc,'Active Directory environments centralize identities, privileges and critical services, making them a primary target for attackers. This project proposes an end-to-end detection approach: document offensive techniques, build an isolated lab, simulate representative attacks, centralize logs with Wazuh, address blind spots with custom rules, and apply machine-learning-based behavioral detection.')
    add_text(doc,'The Azure-hosted GOAD-Light environment includes two domain controllers, one MSSQL server and a Wazuh platform. Twelve attacks were reproduced, seven custom Wazuh rules were validated, and an Isolation Forest model identified four anomalous behaviors, including Pass-the-Hash, Golden Ticket-related behavior, and MSSQL command execution.')
    doc.add_page_break()
    add_heading(doc,'Liste des abréviations',1)
    add_table(doc,['Abréviation','Signification'],[
        ['AD','Active Directory'],['ADCS','Active Directory Certificate Services'],['DC','Domain Controller'],['EDR','Endpoint Detection and Response'],['GPO','Group Policy Object'],['IA','Intelligence Artificielle'],['KDC','Key Distribution Center'],['MITRE ATT&CK','Base de connaissances des tactiques et techniques adverses'],['NTLM','NT LAN Manager'],['SIEM','Security Information and Event Management'],['SOC','Security Operations Center'],['TGT / TGS','Tickets Kerberos d’authentification et de service'],['Wazuh','Plateforme open source de SIEM et XDR'],
    ],[1.6,4.7],9.5)
    doc.add_page_break()
    add_heading(doc,'Sommaire',1)
    add_toc_field(doc)
    doc.add_page_break()

def chapter1(doc):
    add_heading(doc,'Introduction générale',1)
    add_text(doc,'La sécurité des identités est devenue un enjeu central pour les organisations. Active Directory (AD) gère les utilisateurs, les groupes, les postes, les serveurs et les autorisations. Une compromission d’AD peut donc donner accès à l’ensemble du système d’information. Les attaques modernes ne reposent pas uniquement sur des logiciels malveillants visibles : elles exploitent souvent des fonctions légitimes de Windows, de Kerberos ou de l’annuaire, ce qui complique leur détection.')
    add_text(doc,'L’objectif de ce projet est de démontrer, dans un cadre maîtrisé, que la qualité d’un SOC ne dépend pas uniquement de l’installation d’un SIEM. Elle dépend aussi des politiques d’audit, de la qualité des règles de corrélation et de la capacité à reconnaître un comportement anormal. La démarche suivie transforme une simulation offensive en capacité de détection défensive mesurable.')
    add_callout(doc,'PROBLÉMATIQUE', 'Comment construire une chaîne de détection capable d’identifier des attaques Active Directory connues, tout en réduisant les angles morts laissés par les règles de signature ?',PALE)
    add_heading(doc,'Objectifs du projet',2)
    add_numbered(doc,[
        'Constituer une base documentaire de 48 attaques Active Directory, reliées à MITRE ATT&CK et aux événements Windows pertinents.',
        'Déployer un laboratoire vulnérable, isolé et reproductible sur Azure.',
        'Installer Wazuh afin de centraliser les journaux des machines du laboratoire.',
        'Simuler 12 attaques représentatives et mesurer la couverture de détection initiale.',
        'Écrire et valider des règles Wazuh sur mesure pour les signatures exploitables.',
        'Mettre en œuvre une détection d’anomalies non supervisée pour les scénarios difficilement détectables par règle statique.',
    ])
    add_heading(doc,'Démarche méthodologique',2)
    add_table(doc,['Étape','Question traitée','Livrable'],[
        ['1. Documenter','Quelles techniques sont susceptibles de compromettre un AD ?','48 fiches MITRE ATT&CK'],
        ['2. Construire','Comment reproduire ces techniques sans risque ?','Lab GOAD-Light isolé sur Azure'],
        ['3. Observer','Quels journaux et alertes sont générés ?','Wazuh + agents Windows'],
        ['4. Mesurer','Quels scénarios restent invisibles ?','Matrice de détection de 12 attaques'],
        ['5. Corriger','Quels signaux peuvent devenir des alertes fiables ?','7 règles Wazuh personnalisées'],
        ['6. Compléter','Comment détecter les comportements sans signature ?','Agent IA Isolation Forest'],
    ],[1.0,3.0,2.3],9)
    add_heading(doc,'Organisation du rapport',2)
    add_text(doc,'Le premier chapitre présente le contexte du stage et la problématique de détection. Le deuxième décrit le cadrage, l’architecture du laboratoire et les choix techniques. Le troisième détaille la réalisation : simulations, règles Wazuh, agent IA et résultats. Le rapport se termine par un bilan, les limites rencontrées et les perspectives d’évolution.')
    doc.add_page_break()

def chapter2(doc):
    add_heading(doc,'Chapitre 1 — Contexte du stage et présentation de la mission',1)
    add_heading(doc,'1. Présentation de l’organisme d’accueil',2)
    add_text(doc,'Le projet a été réalisé dans le cadre de Dataprotect, au sein de la Business Unit Security Intelligence / SOC. Le SOC a pour rôle de surveiller les événements de sécurité, d’analyser les alertes, de qualifier les incidents et de coordonner la réponse. Dans ce contexte, la détection des attaques visant les identités Active Directory constitue un sujet majeur : elle relie la supervision des endpoints, l’analyse des authentifications, la gestion des privilèges et la réponse à incident.')
    add_callout(doc,'NOTE DE PERSONNALISATION', 'Les informations institutionnelles détaillées de Dataprotect (historique, effectif, organigramme, clientèle et partenaires) doivent être complétées ou validées par l’étudiant avant dépôt final, afin de ne présenter que des données officiellement autorisées.', 'FFF7E6')
    add_heading(doc,'2. Département d’accueil : Security Intelligence / SOC',2)
    add_text(doc,'Un SOC transforme de grands volumes de journaux techniques en décisions opérationnelles. Les analystes surveillent les alertes, corrèlent les événements provenant des différentes sources, enquêtent sur les comportements suspects et proposent des mesures de remédiation. Le présent projet s’inscrit dans cette chaîne : il ne cherche pas à “attaquer” un système réel, mais à comprendre les traces laissées par les attaques afin d’améliorer les capacités défensives.')
    add_table(doc,['Fonction SOC','Lien avec le projet'],[
        ['Collecte','Les agents Wazuh collectent les événements Windows des contrôleurs de domaine et du serveur MSSQL.'],
        ['Détection','Les règles Wazuh convertissent des événements précis en alertes priorisées.'],
        ['Investigation','Les recherches OpenSearch/Wazuh permettent d’associer utilisateur, machine, IP source, processus et événement.'],
        ['Amélioration continue','Les angles morts observés en simulation conduisent à activer de nouveaux audits et à créer de nouvelles règles.'],
        ['Innovation','Le modèle IA complète les règles de signature par une détection comportementale.'],
    ],[1.45,4.85],9.5)
    add_heading(doc,'3. Mission confiée',2)
    add_text(doc,'La mission consistait à concevoir une preuve de concept de détection des attaques Active Directory. Elle devait être pédagogique, reproductible, documentée et techniquement démontrable. Le périmètre retenu comprend la construction du laboratoire, l’intégration Wazuh, la simulation de douze scénarios, l’écriture de règles de détection et une première couche d’intelligence artificielle.')
    add_heading(doc,'4. Positionnement et cadre éthique',2)
    add_text(doc,'Toutes les opérations décrites dans ce rapport sont limitées à un environnement de laboratoire isolé. Aucun test n’a été réalisé contre une infrastructure réelle ou sans autorisation explicite. Les identifiants, clés, hashs et secrets utilisés dans le laboratoire ne sont pas reproduits dans ce rapport. Cette séparation est essentielle : l’objectif est d’améliorer la détection, la prévention et la réponse à incident.')
    doc.add_page_break()
    add_heading(doc,'Chapitre 2 — Analyse du besoin et conception de la solution',1)
    add_heading(doc,'1. Besoin initial',2)
    add_text(doc,'Une installation SIEM standard collecte des journaux, mais ne garantit pas que les événements utiles soient générés ni que les scénarios d’attaque soient identifiés. Le besoin est donc double : vérifier la visibilité réelle des attaques Active Directory et construire une approche graduelle pour combler les lacunes observées.')
    add_table(doc,['Exigence','Réponse apportée'],[
        ['Isoler le risque','Laboratoire GOAD-Light exécuté sur une VM Azure, réseau interne 192.168.56.0/24.'],
        ['Centraliser les journaux','Wazuh indexer, manager et dashboard ; agents sur les trois machines Windows.'],
        ['Reproduire des scénarios réalistes','12 attaques choisies sur une kill chain AD : reconnaissance, vol d’identifiants, élévation, mouvement latéral et persistance.'],
        ['Mesurer objectivement la couverture','Recherche des Event IDs, observation des alertes, tableau de statut par scénario.'],
        ['Réduire les angles morts','Activation d’audits Windows et règles Wazuh à partir d’événements validés.'],
        ['Détecter l’inconnu','Isolation Forest sur des caractéristiques comportementales agrégées par compte.'],
    ],[1.85,4.45],9.2)
    add_heading(doc,'2. Architecture fonctionnelle',2)
    add_text(doc,'La solution est composée de deux domaines Active Directory reliés par un trust et d’un serveur membre MSSQL. Ces systèmes transmettent leurs journaux à Wazuh. Les alertes sont stockées dans OpenSearch, interrogées lors de l’investigation, puis exportées au format JSON pour l’analyse comportementale.')
    add_table(doc,['Composant','Adresse du lab','Rôle'],[
        ['kingslanding (DC01)','192.168.56.10','Contrôleur de domaine de sevenkingdoms.local ; héberge également la CA ADCS.'],
        ['winterfell (DC02)','192.168.56.11','Contrôleur de domaine de north.sevenkingdoms.local.'],
        ['castelblack (SRV02)','192.168.56.22','Serveur membre hébergeant SQL Server Express.'],
        ['Wazuh','192.168.56.51','Indexer, manager, dashboard et stockage des alertes.'],
        ['goad-host','Hôte Azure','Exécute GOAD-Light et sert de point de simulation autorisé.'],
    ],[1.55,1.2,3.55],9.2)
    add_heading(doc,'3. Planification',2)
    add_table(doc,['Phase','Travaux réalisés','Résultat'],[
        ['Phase 1','Documentation des techniques AD','48 fiches classées MITRE ATT&CK.'],
        ['Phase 2','Déploiement Azure + GOAD-Light','Lab AD vulnérable isolé et opérationnel.'],
        ['Phase 3','Installation Wazuh et agents','Collecte active sur trois hôtes Windows.'],
        ['Phase 4','Simulation et observation','12 scénarios rejoués ; 2 détections natives, 4 partielles, 6 angles morts.'],
        ['Phase 5','Audit Windows + règles Wazuh','7 règles sur mesure validées en laboratoire.'],
        ['Phase 6','Détection IA','Isolation Forest sur alertes Wazuh et identification d’anomalies.'],
    ],[1.0,3.2,2.1],9.2)
    doc.add_page_break()

def chapter3(doc):
    add_heading(doc,'Chapitre 3 — Réalisation technique et résultats',1)
    add_heading(doc,'1. Phase 1 : documentation et modèle de menace',2)
    add_text(doc,'La première phase a constitué une base de connaissance de 48 techniques Active Directory, réparties selon les tactiques MITRE ATT&CK : reconnaissance, accès aux identifiants, mouvement latéral, élévation de privilèges, persistance, évasion de défense et abus de trusts. Chaque fiche explique le principe de l’attaque, les prérequis, les événements attendus, les pistes de détection et les mesures de remédiation.')
    add_heading(doc,'2. Phase 2 : construction du laboratoire',2)
    add_text(doc,'Le laboratoire GOAD-Light a été choisi car il fournit un environnement Active Directory volontairement vulnérable mais isolé. Il permet de manipuler des domaines, des relations de confiance, des comptes de service, une autorité de certification et un serveur SQL, sans exposer de système de production. Le déploiement sur Azure a permis de disposer de ressources suffisantes pour l’exécution de plusieurs machines virtuelles imbriquées.')
    add_heading(doc,'3. Phase 3 : intégration de Wazuh',2)
    add_text(doc,'Wazuh centralise les événements Windows, applique son moteur de règles et présente les alertes dans le dashboard. Une chaîne de classification des événements est utilisée : décodage Windows EventChannel, identification du canal Security, puis qualification du succès ou de l’échec d’audit. Les règles personnalisées ajoutées par la suite reposent sur cette chaîne afin de s’intégrer proprement au ruleset existant.')
    add_heading(doc,'4. Phase 4 : simulation des attaques et diagnostic initial',2)
    add_text(doc,'Douze attaques ont été rejouées afin de mesurer la visibilité native. Cette phase a mis en évidence un constat essentiel : de nombreuses lacunes ne provenaient pas d’un dysfonctionnement de Wazuh, mais d’événements Windows non générés faute de politique d’audit active. Le SIEM ne peut pas détecter un signal qui n’existe pas dans les journaux.')
    add_table(doc,['#','Scénario','Signal observé initialement','Diagnostic'],[
        ['01','Kerberoasting','4769 visible mais non spécifique','Détection partielle.'],['02','AS-REP Roasting','4768 absent','Audit Kerberos non activé.'],['03','Énumération LDAP','4662 absent','Audit/SACL insuffisants ; bruit potentiel.'],['04','LLMNR Poisoning','Pas de journal Windows utile','Attaque réseau, hors périmètre SIEM hôte.'],['05','Password Spraying','Rafale 4625','Détecté nativement.'],['06','DCSync','4662 absent','Angle mort critique : audit DS Access absent.'],['07','Abus ACL','4728 présent','Détecté nativement.'],['08','ADCS ESC1','4887 et 4768 absents','Audits ADCS/Kerberos absents.'],['09','Pass-the-Hash','4624 NTLM type 3','Visible mais ambigu.'],['10','MSSQL RCE','4688 absent','Audit de création de processus absent.'],['11','Golden Ticket','Logons cohérents mais inhabituels','Signature insuffisante.'],['12','Trust abuse','Logon cross-domain ambigu','Signature insuffisante.'],
    ],[0.35,1.35,2.55,2.05],8.4)
    add_heading(doc,'5. Phase 5 : activation des audits et règles Wazuh personnalisées',2)
    add_text(doc,'Les catégories d’audit nécessaires ont été activées sur les contrôleurs de domaine : accès aux services d’annuaire, authentification Kerberos, opérations de tickets de service, services de certification et création de processus. La ligne de commande des processus a également été activée, car elle augmente fortement la qualité de l’investigation.')
    add_table(doc,['Règle','Événement et condition','Objectif','Validation'],[
        ['100010','4662 — accès à la réplication AD','Détecter un DCSync','Validée en laboratoire.'],
        ['100011','4769 + chiffrement RC4 (0x17)','Détecter un Kerberoasting','3 alertes observées.'],
        ['100012','4887 — certificat émis','Détecter un abus ADCS ESC1','2 alertes observées.'],
        ['100013','4688 + parent sqlservr.exe','Détecter xp_cmdshell/MSSQL RCE','7 alertes observées.'],
        ['100014','4768 + preAuthType=0','Détecter AS-REP Roasting','1 alerte observée.'],
        ['100017','4624 + type 3 + NTLM','Signaler un possible Pass-the-Hash','5 alertes observées.'],
        ['100019','Enfant de 100017 + domaine NORTH','Identifier un logon cross-domain suspect','18 alertes observées.'],
    ],[0.75,2.3,2.1,1.7],8.5)
    add_callout(doc,'LEÇON CLÉ', 'Une règle de détection n’est fiable que si le bon événement est audité, collecté, correctement décodé et suffisamment spécifique pour limiter les faux positifs.',PALE)
    add_heading(doc,'6. Limites de la détection par signature',2)
    add_text(doc,'Deux cas illustrent les limites structurelles des règles : LLMNR Poisoning est une attaque réseau qui nécessite une visibilité NDR telle que Zeek ou Suricata ; l’énumération LDAP requiert des SACL au niveau des objets, ce qui peut produire un volume de 4662 difficilement exploitable. De plus, un Golden Ticket bien forgé est cryptographiquement valide : le contrôleur de domaine ne peut pas simplement le distinguer d’un ticket légitime à partir d’un champ isolé.')
    doc.add_page_break()

def chapter4(doc):
    add_heading(doc,'Chapitre 4 — Agent IA de détection d’anomalies',1)
    add_heading(doc,'1. Pourquoi compléter les règles par une approche comportementale ?',2)
    add_text(doc,'Les règles Wazuh sont efficaces lorsqu’une attaque possède une signature stable. En revanche, certaines activités malveillantes ont des valeurs techniques valides : un logon NTLM peut être légitime, un ticket Kerberos peut être correctement signé et une requête LDAP peut ressembler à une requête applicative. Dans ces cas, ce n’est pas forcément l’événement isolé qui est suspect, mais son volume, son heure, son origine ou sa séquence.')
    add_table(doc,['Approche','Atout','Limite','Exemple'],[
        ['Règle de signature','Explicable, rapide, précise','Dépend d’un motif connu','4688 dont le parent est sqlservr.exe.'],
        ['Détection comportementale','Repère des écarts au comportement habituel','Peut générer des faux positifs et nécessite une baseline','Compte avec volume NTLM ou tickets inhabituel.'],
    ],[1.55,1.7,1.8,1.45],9.2)
    add_heading(doc,'2. Pipeline de données',2)
    add_text(doc,'Les alertes Wazuh sont extraites depuis OpenSearch au format JSON. Le script Python agrège les événements sur une fenêtre de 24 heures par compte non-machine, normalise les valeurs puis applique le modèle Isolation Forest. Chaque compte obtient un score : plus le score est faible, plus son comportement est éloigné du profil habituel observé dans le jeu de données.')
    add_callout(doc,'CHAÎNE DE TRAITEMENT', 'Wazuh / OpenSearch → export JSON → construction de caractéristiques par compte → normalisation → Isolation Forest → classement des comptes à investiguer.',PALE)
    add_heading(doc,'3. Caractéristiques utilisées',2)
    add_table(doc,['Feature','Interprétation sécurité'],[
        ['nb_events','Volume total d’activité du compte.'],['nb_custom','Nombre d’alertes issues des règles personnalisées.'],['nb_ntlm / ntlm_ratio','Usage NTLM et proportion par rapport à Kerberos ; utile pour PtH.'],['nb_type3','Nombre de connexions réseau ; indicateur de mouvement latéral.'],['nb_ips','Diversité des IP sources utilisées.'],['nb_night','Activité entre 22 h et 6 h.'],['nb_4662','Accès Directory Service, indicateur de reconnaissance à investiguer.'],['tgs_without_tgt','Différence entre TGS (4769) et TGT (4768), utile pour analyser des tickets anormaux.'],['rule_level_max','Niveau de gravité maximal associé au compte.'],
    ],[2.2,4.3],9.2)
    add_heading(doc,'4. Choix du modèle',2)
    add_text(doc,'Isolation Forest est un algorithme de détection d’anomalies non supervisé. Il est pertinent dans ce contexte car les journaux réels sont rarement annotés de manière fiable en “normal” ou “attaque”. Le modèle construit 200 arbres aléatoires ; les observations rares sont isolées plus rapidement et reçoivent un score d’anomalie plus faible. Le taux de contamination a été fixé à 15 % pour le jeu de données de laboratoire, riche en activités de simulation.')
    add_heading(doc,'5. Résultats obtenus',2)
    add_text(doc,'L’analyse a porté sur 5 000 alertes Wazuh des dernières 24 heures et 23 comptes non-machine. Quatre comptes ont été classés comme anomalies. Ces résultats ne remplacent pas l’analyste : ils servent à prioriser les investigations et à expliquer quels comportements méritent une vérification.')
    add_table(doc,['Compte / profil','Score','Indicateurs remarquables','Interprétation'],[
        ['robb.stark','-0,170','1 461 événements ; activité automatisée','Bot RDP : volume anormal mais attendu dans le lab.'],
        ['eddard.stark','-0,086','17 logons NTLM ; alertes custom','Comportement cohérent avec le scénario Pass-the-Hash.'],
        ['robb.stark@NORTH','-0,083','610 TGS sans TGT associé','Comportement Golden Ticket à investiguer.'],
        ['sql_svc','-0,022','Alertes custom ; type 3 ; NTLM','Activité cohérente avec MSSQL RCE/xp_cmdshell.'],
    ],[1.35,0.7,2.2,2.25],8.6)
    add_heading(doc,'6. Interprétation et limites',2)
    add_text(doc,'Les résultats confirment l’intérêt de combiner règles et IA. Les alertes de règles renforcent la compréhension de l’anomalie, tandis que les caractéristiques comportementales permettent de faire ressortir des séquences difficiles à exprimer sous forme de signature. La principale limite est la taille réduite et volontairement atypique du lab : en production, une phase d’apprentissage plus longue, un inventaire des comptes de service et une validation humaine des alertes sont indispensables.')
    doc.add_page_break()

def conclusion(doc):
    add_heading(doc,'Conclusion générale',1)
    add_text(doc,'Ce projet a permis de mettre en œuvre une chaîne de détection Active Directory complète, allant de l’étude théorique des attaques jusqu’à l’exploitation opérationnelle d’alertes SIEM et à la détection d’anomalies par intelligence artificielle. Le résultat principal est démonstratif : une attaque peut être techniquement très grave tout en étant invisible pour un SIEM si les bons audits Windows ne sont pas activés.')
    add_text(doc,'La simulation de douze scénarios a révélé deux détections natives, quatre cas partiellement visibles et six angles morts initiaux. L’activation d’audits ciblés et la création de sept règles Wazuh ont permis de transformer plusieurs de ces angles morts en alertes exploitables. Pour les scénarios sans signature fiable, l’agent Isolation Forest a montré une capacité à faire émerger des comportements inhabituels à partir de la fréquence, du type d’authentification, des horaires, des IP sources et de la séquence des tickets Kerberos.')
    add_heading(doc,'Apports personnels et compétences acquises',2)
    add_bullets(doc,[
        'Compréhension opérationnelle d’Active Directory, Kerberos, NTLM, ADCS et des relations de confiance.',
        'Maîtrise de la mise en place d’un laboratoire isolé basé sur GOAD-Light, VirtualBox et Azure.',
        'Déploiement et exploitation de Wazuh : agents, événements Windows, règles, recherche et investigation.',
        'Conception de règles de détection alignées sur MITRE ATT&CK et validation par simulation contrôlée.',
        'Initiation pratique à la détection d’anomalies avec Python, pandas, scikit-learn et Isolation Forest.',
        'Adoption d’une démarche SOC : observer, corréler, expliquer, remédier et améliorer en continu.',
    ])
    add_heading(doc,'Perspectives',2)
    add_numbered(doc,[
        'Industrialiser la collecte via des politiques de groupe (GPO) et documenter une baseline de production.',
        'Ajouter une composante NDR, par exemple Zeek ou Suricata, pour couvrir les attaques purement réseau telles que LLMNR Poisoning.',
        'Enrichir le modèle IA avec une période d’apprentissage plus longue, des profils de comptes de service et des retours analyste.',
        'Connecter les alertes prioritaires à un outil SOAR afin d’automatiser la collecte de contexte et les premières actions de réponse.',
        'Étendre les simulations aux autres techniques documentées afin de renforcer progressivement la couverture de détection.',
    ])
    doc.add_page_break()
    add_heading(doc,'Bibliographie et ressources',1)
    add_bullets(doc,[
        'MITRE ATT&CK. Enterprise Techniques : https://attack.mitre.org/',
        'Wazuh Documentation. Windows event log collection and rules : https://documentation.wazuh.com/',
        'Orange Cyberdefense. Game of Active Directory (GOAD) : https://github.com/Orange-Cyberdefense/GOAD',
        'scikit-learn Documentation. IsolationForest : https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html',
        'Microsoft Learn. Advanced audit policy configuration and Windows Security Auditing.',
    ])
    doc.add_page_break()
    add_heading(doc,'Annexe A — Catalogue des règles Wazuh',1)
    add_text(doc,'Les règles suivantes sont installées dans le fichier local_rules.xml du manager Wazuh. Les extraits sont volontairement limités aux conditions de détection ; aucun secret d’environnement n’est inclus.')
    add_table(doc,['ID','Technique','Logique de détection'],[
        ['100010','DCSync','Event 4662 — utilisation de droits de réplication AD.'],['100011','Kerberoasting','Event 4769 et chiffrement RC4 0x17.'],['100012','ADCS ESC1','Event 4887 — certificat émis.'],['100013','MSSQL RCE','Event 4688 avec processus parent sqlservr.exe.'],['100014','AS-REP Roasting','Event 4768 et preAuthType égal à 0.'],['100017','Pass-the-Hash','Event 4624, logonType 3 et paquet NTLM.'],['100019','Trust abuse','Affinage de 100017 pour logon cross-domain NORTH.'],
    ],[0.75,1.6,4.15],9.2)
    add_heading(doc,'Annexe B — Procédure de lancement de l’agent IA',1)
    add_numbered(doc,[
        'Exporter une fenêtre d’alertes Wazuh depuis OpenSearch au format JSON.',
        'Installer les dépendances Python nécessaires : pandas, numpy et scikit-learn.',
        'Exécuter le script detection/anomaly_detection.py en indiquant le fichier JSON exporté.',
        'Consulter le classement et investiguer les comptes ayant les scores les plus faibles.',
        'Valider chaque anomalie avec le contexte Wazuh afin de distinguer activité légitime et scénario malveillant.',
    ])

def main():
    shutil.copy2(TEMPLATE, OUT)
    doc=Document(OUT)
    clear_doc(doc)
    sec=doc.sections[0]
    sec.top_margin=Inches(0.8); sec.bottom_margin=Inches(0.8); sec.left_margin=Inches(0.85); sec.right_margin=Inches(0.85)
    sec.header_distance=Inches(0.35); sec.footer_distance=Inches(0.35)
    configure_styles(doc); add_header_footer(sec)
    doc._bullet_num_id = add_numbering_definition(doc, bullet=True)
    doc._decimal_num_id = add_numbering_definition(doc, bullet=False)
    cover(doc); front_matter(doc); chapter1(doc); chapter2(doc); chapter3(doc); chapter4(doc); conclusion(doc)
    doc.core_properties.title='Détection des attaques Active Directory par Wazuh et IA'
    doc.core_properties.subject='Rapport de Projet de Fin d’Études'
    doc.core_properties.author='[À compléter]'
    doc.settings.element.append(OxmlElement('w:updateFields'))
    doc.save(OUT)
    print(OUT)

if __name__=='__main__': main()
