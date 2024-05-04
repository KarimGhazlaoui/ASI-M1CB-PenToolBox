import csv

class gvm:
    def __init__(self) -> None:
        pass

    def traitement_csv(self, donnee_csv):
        scan_resultat = []
        lines = donnee_csv.strip().split('\n')
        header = lines[0].strip().split(',')
        reader = csv.DictReader(lines[1:], fieldnames=header)
        for row in reader:
            scan_resultat.append({
                'IP': row.get('IP', ''),
                'Port': row.get('Port', ''),
                'Protocole': row.get('Port Protocol', ''),
                'Sévérité': row.get('Severity', ''),
                'NVT': row.get('NVT Name', ''),
                'CVE': row.get('CVEs', '')
            })
        return scan_resultat
