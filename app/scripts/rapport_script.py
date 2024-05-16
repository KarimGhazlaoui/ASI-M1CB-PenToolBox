from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, PageBreak, Image
from datetime import datetime
import json
import os
from bs4 import BeautifulSoup

class RapportGenerateur:
    def __init__(self, profile):
        self.profile = profile
        self.current_dir = os.path.dirname(os.path.abspath(__file__))

    def preprocess_hydra_scan_result(self, hydra_scan_result):
        # Parse the Hydra scan result to extract table data
        lines = hydra_scan_result.split("\n")
        table_data = []
        for line in lines:
            if line.startswith("[21][ftp]"):
                parts = line.split()
                ip = parts[2]
                login = parts[4]
                password = parts[6]
                table_data.append(["21", "ftp", ip, login, password])
        return table_data


    def generate_hydra_table(self, data, header_style, cell_style):
        table_data = [["PORT", "PROTOCOL", "IP", "LOGIN", "PASSWORD"]]
        table_data.extend(data)
        
        hydra_table = Table(table_data, repeatRows=1)
        hydra_table._argW = [50, 100, 100, 200, 200]  # Adjust column widths as needed
        hydra_table._tblwidth = "100%"
        hydra_table.setStyle(TableStyle([('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                                        ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                                        ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
                                        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                                        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                                        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                                        ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
                                        ('ALIGN', (-1, 0), (-1, -1), 'LEFT')
                                        ]))
        return hydra_table

    def generate_pdf_report(self, filename, toolname, subnet_scanned=None, target_discovered=None, cve_discovered=None, hydra_scan_result=None):
        try:
            doc = SimpleDocTemplate(filename, pagesize=landscape(letter))
            styles = getSampleStyleSheet()
            title_style = styles["Title"]
            title_style.alignment = 1  
            table_header_style = styles["Heading3"]
            table_header_style.alignment = 1  
            table_cell_style = styles["Normal"]
            table_cell_style.alignment = 1  

            now = datetime.now()
            current_date_time = now.strftime("%d/%m/%Y %H:%M:%S")

            # Add logo
            logo_path = os.path.join(self.current_dir, "..", "resource", "images", "logo.png")  # Replace with the actual path to your logo
            logo = Image(logo_path, width=100, height=100)

            content = [
                logo,  # Add the logo to the content list
                Paragraph(f"<u>{toolname}</u>", title_style),
                Paragraph(f"<b>Date et Heure:</b> {current_date_time}", styles["Normal"]),
                Paragraph("<br/>", styles["Normal"])  
            ]

            if subnet_scanned:
                content.append(Paragraph(f"<b>Réseau Scanné:</b> {subnet_scanned}", styles["Normal"]))
            else:
                content.append(Paragraph("<i>Aucune information sur le réseau scanné disponible.</i>", styles["Italic"]))
            content.append(Paragraph("<br/>", styles["Normal"]))

            if target_discovered:
                # Generate Target Table
                target_table = self.generate_target_table(target_discovered, table_header_style, table_cell_style)
                content.append(target_table)
                content.append(Paragraph("<br/>", styles["Normal"]))

            if cve_discovered:
                content.append(Paragraph("<b>Vulnérabilités Découvertes:</b>", table_header_style))
                # Generate CVE table
                cve_table = self.generate_cve_table(cve_discovered, table_header_style, table_cell_style)
                content.append(cve_table)
                content.append(Paragraph("<br/>", styles["Normal"]))
                # Page break before Hydra scan result
                content.append(PageBreak())
            else:
                content.append(Paragraph("<i>Aucune information sur les CVE découvertes disponible.</i>", styles["Italic"]))
                content.append(Paragraph("<br/>", styles["Normal"]))

            if hydra_scan_result:
                # Add main title for Hydra scan result
                content.append(Paragraph("<b>Exploitation - Evaluation des Vulnérabilités</b>", table_header_style))
                content.append(Paragraph("<br/>", styles["Normal"]))
                
                # Preprocess Hydra scan result to extract table data
                hydra_table_data = self.preprocess_hydra_scan_result(hydra_scan_result)
                if hydra_table_data:
                    content.append(Paragraph("<b>Résultat de l'attaque Hydra :</b>", table_header_style))
                    hydra_table = self.generate_hydra_table(hydra_table_data, table_header_style, table_cell_style)
                    content.append(hydra_table)
                else:
                    content.append(Paragraph("<i>Aucun résultat de l'attaque Hydra disponible.</i>", styles["Italic"]))
            else:
                content.append(Paragraph("<i>Aucun résultat de l'attaque Hydra disponible.</i>", styles["Italic"]))

            doc.build(content)
            print("PDF generated successfully!")
        except Exception as e:
            print("Error:", e)

    def generate_cve_table(self, cve_data, header_style, cell_style):
        table_data = [["IP", "CVE", "Description", "Sévérité"]]
        for entry in cve_data:
            ip = entry.get("IP", "")
            cve = entry.get("CVE", "")
            description = entry.get("Description", "")
            severity = entry.get("Sévérité", "")
            table_data.append([ip, cve, description, severity])

        cve_table = Table(table_data, repeatRows=1)
        cve_table._argW = [70, 100, 500, 50]  
        cve_table._tblwidth = "100%"
        cve_table.setStyle(TableStyle([('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                                    ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                                    ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
                                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                                    ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                                    ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
                                    ('ALIGN', (-1, 0), (-1, -1), 'CENTER')
                                    ]))
        return cve_table

    def generate_target_table(self, target_data, header_style, cell_style):
        table_data = [["Discovered Targets"]]
        for target in target_data:
            table_data.append([target])

        target_table = Table(table_data, repeatRows=1)
        target_table._argW = [200]
        target_table._tblwidth = "100%"
        target_table.setStyle(TableStyle([('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                                        ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                                        ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
                                        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                                        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                                        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                                        ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
                                        ('ALIGN', (-1, 0), (-1, -1), 'CENTER')
                                        ]))
        return target_table

    # Remove HTML tags from text
    def remove_html_tags(self, text):
        soup = BeautifulSoup(text, "html.parser")
        return soup.get_text()

    # Function to read data from JSON file
    def read_json(self, filename):
        with open(filename, 'r') as file:
            data = json.load(file)
        return data

    # Function to extract relevant information from JSON data
    def extract_info(self, data):
        toolname = "KGB - PenToolBox"
        subnet_scanned = data.get("reseau_cible", "")
        targets = data.get("cible_detecte", [])
        target_discovered = [target[0] for target in targets] if targets else []
        
        cve_list = []
        vulnerabilities = data.get("vulnerabilite_detecte", [])
        for vuln in vulnerabilities:
            if vuln["CVE"]:
                cve_list.append({
                    "IP": vuln["IP"],
                    "CVE": vuln["CVE"].split(',')[0],
                    "Description": vuln["NVT"],
                    "Sévérité": vuln["Sévérité"]
                })
        
        hydra_scan_result = data.get("hydra_resultat", "")

        return toolname, subnet_scanned, target_discovered, cve_list, hydra_scan_result
    
    def GenererRapport(self, Profile, file_path):

        if Profile:
            # Path to the JSON file
            json_file_path = os.path.join(self.current_dir, "..", "profiles", Profile + ".kgb")

            # Read data from JSON file using self.read_json
            data = self.read_json(json_file_path)

            # Extract relevant information
            toolname, subnet_scanned, target_discovered, cve_discovered, hydra_scan_result = self.extract_info(data)

            # Generate PDF report
            self.generate_pdf_report(file_path, toolname, subnet_scanned, target_discovered, cve_discovered, hydra_scan_result)
        else:
            return

