import sys
import xml.etree.ElementTree as ET
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem
import re

def fix_xml_output(xml_data):
    # Define a regular expression pattern to find the 'output' attribute
    pattern = r'(<script id="vulners" output=")(.*?)(".*?</script>)'

    # Use re.sub() to replace the 'output' attribute with the corrected one
    corrected_xml_data = re.sub(pattern, r'\1<![CDATA[\2]]>\3', xml_data)

    return corrected_xml_data

class VulnerabilityTable(QMainWindow):
    def __init__(self, data):
        super().__init__()
        self.data = data
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Vulnerability Table')
        self.setGeometry(100, 100, 800, 600)

        self.tableWidget = QTableWidget()
        self.tableWidget.setRowCount(len(self.data))
        self.tableWidget.setColumnCount(4)
        self.tableWidget.setHorizontalHeaderLabels(["Port", "CVE ID", "CVSS", "Exploit"])

        for i, vulnerability in enumerate(self.data):
            port = vulnerability["port"]
            cve_id = vulnerability["cve_id"]
            cvss = vulnerability["cvss"]
            exploit = vulnerability["exploit"]
            self.tableWidget.setItem(i, 0, QTableWidgetItem(str(port)))
            self.tableWidget.setItem(i, 1, QTableWidgetItem(cve_id))
            self.tableWidget.setItem(i, 2, QTableWidgetItem(str(cvss)))
            self.tableWidget.setItem(i, 3, QTableWidgetItem(str(exploit)))

        self.setCentralWidget(self.tableWidget)

def parse_xml(xml_data):
    # Fix XML data
    xml_data_fixed = fix_xml_output(xml_data)

    vulnerabilities = []
    try:
        root = ET.fromstring(xml_data_fixed)
        for port_node in root.findall('.//port'):
            port = port_node.attrib['portid']
            for script_node in port_node.findall('.//script[@id="vulners"]'):
                output = script_node.attrib['output']
                cve_start_index = output.find('CVE-')
                while cve_start_index != -1:
                    cve_end_index = output.find('CVE-', cve_start_index + 1)
                    if cve_end_index == -1:
                        cve_end_index = len(output)
                    cve_str = output[cve_start_index:cve_end_index]
                    cve_id = cve_str.split()[0]
                    cvss = float(cve_str.split()[1])
                    exploit = '*' if '*EXPLOIT*' in cve_str else ''
                    vulnerabilities.append({"port": port, "cve_id": cve_id, "cvss": cvss, "exploit": exploit})
                    cve_start_index = output.find('CVE-', cve_end_index)
    except ET.ParseError as e:
        print("Error parsing XML:", e)
    return vulnerabilities

if __name__ == '__main__':
    # XML data stored in a variable
    xml_data = """
    <?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.94SVN scan initiated Mon May  6 21:18:18 2024 as: nmap -&#45;script nmap-vulners/vulners.nse,vulscan/vulscan.nse -&#45;script-args vulscandb=scipvuldb.csv -sV -p22 -oX - 192.168.1.29 -->
<nmaprun scanner="nmap" args="nmap -&#45;script nmap-vulners/vulners.nse,vulscan/vulscan.nse -&#45;script-args vulscandb=scipvuldb.csv -sV -p22 -oX - 192.168.1.29" start="1715023098" startstr="Mon May  6 21:18:18 2024" version="7.94SVN" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="1" services="22"/>
<verbose level="0"/>
<debugging level="0"/>
<hosthint><status state="up" reason="unknown-response" reason_ttl="0"/>
<address addr="192.168.1.29" addrtype="ipv4"/>
<hostnames>
</hostnames>
</hosthint>
<host starttime="1715023099" endtime="1715023100"><status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="192.168.1.29" addrtype="ipv4"/>
<hostnames>
</hostnames>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" product="OpenSSH" version="4.7p1 Debian 8ubuntu1" extrainfo="protocol 2.0" ostype="Linux" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:4.7p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service><script id="vulscan"Bug in vulscan: no string output.
 output=""/><script id="vulners" output="&#xa;  cpe:/a:openbsd:openssh:4.7p1: &#xa;    &#x9;SSV:78173&#x9;7.8&#x9;https://vulners.com/seebug/SSV:78173&#x9;*EXPLOIT*&#xa;    &#x9;SSV:69983&#x9;7.8&#x9;https://vulners.com/seebug/SSV:69983&#x9;*EXPLOIT*&#xa;    &#x9;EDB-ID:24450&#x9;7.8&#x9;https://vulners.com/exploitdb/EDB-ID:24450&#x9;*EXPLOIT*&#xa;    &#x9;EDB-ID:15215&#x9;7.8&#x9;https://vulners.com/exploitdb/EDB-ID:15215&#x9;*EXPLOIT*&#xa;    &#x9;SECURITYVULNS:VULN:8166&#x9;7.5&#x9;https://vulners.com/securityvulns/SECURITYVULNS:VULN:8166&#xa;    &#x9;PRION:CVE-2010-4478&#x9;7.5&#x9;https://vulners.com/prion/PRION:CVE-2010-4478&#xa;    &#x9;CVE-2012-1577&#x9;7.5&#x9;https://vulners.com/cve/CVE-2012-1577&#xa;    &#x9;CVE-2010-4478&#x9;7.5&#x9;https://vulners.com/cve/CVE-2010-4478&#xa;    &#x9;SSV:20512&#x9;7.2&#x9;https://vulners.com/seebug/SSV:20512&#x9;*EXPLOIT*&#xa;    &#x9;PRION:CVE-2011-1013&#x9;7.2&#x9;https://vulners.com/prion/PRION:CVE-2011-1013&#xa;    &#x9;PRION:CVE-2008-1657&#x9;6.5&#x9;https://vulners.com/prion/PRION:CVE-2008-1657&#xa;    &#x9;CVE-2008-1657&#x9;6.5&#x9;https://vulners.com/cve/CVE-2008-1657&#xa;    &#x9;SSV:60656&#x9;5.0&#x9;https://vulners.com/seebug/SSV:60656&#x9;*EXPLOIT*&#xa;    &#x9;PRION:CVE-2011-2168&#x9;5.0&#x9;https://vulners.com/prion/PRION:CVE-2011-2168&#xa;    &#x9;PRION:CVE-2010-5107&#x9;5.0&#x9;https://vulners.com/prion/PRION:CVE-2010-5107&#xa;    &#x9;CVE-2010-5107&#x9;5.0&#x9;https://vulners.com/cve/CVE-2010-5107&#xa;    &#x9;CVE-2010-4816&#x9;5.0&#x9;https://vulners.com/cve/CVE-2010-4816&#xa;    &#x9;PRION:CVE-2010-4755&#x9;4.0&#x9;https://vulners.com/prion/PRION:CVE-2010-4755&#xa;    &#x9;PRION:CVE-2010-4754&#x9;4.0&#x9;https://vulners.com/prion/PRION:CVE-2010-4754&#xa;    &#x9;PRION:CVE-2012-0814&#x9;3.5&#x9;https://vulners.com/prion/PRION:CVE-2012-0814&#xa;    &#x9;PRION:CVE-2011-5000&#x9;3.5&#x9;https://vulners.com/prion/PRION:CVE-2011-5000&#xa;    &#x9;CVE-2023-51767&#x9;3.5&#x9;https://vulners.com/cve/CVE-2023-51767&#xa;    &#x9;CVE-2012-0814&#x9;3.5&#x9;https://vulners.com/cve/CVE-2012-0814&#xa;    &#x9;CVE-2011-5000&#x9;3.5&#x9;https://vulners.com/cve/CVE-2011-5000&#xa;    &#x9;PRION:CVE-2011-4327&#x9;2.1&#x9;https://vulners.com/prion/PRION:CVE-2011-4327&#xa;    &#x9;CVE-2011-4327&#x9;2.1&#x9;https://vulners.com/cve/CVE-2011-4327&#xa;    &#x9;PRION:CVE-2008-3259&#x9;1.2&#x9;https://vulners.com/prion/PRION:CVE-2008-3259&#xa;    &#x9;CVE-2008-3259&#x9;1.2&#x9;https://vulners.com/cve/CVE-2008-3259&#xa;    &#x9;SECURITYVULNS:VULN:9455&#x9;0.0&#x9;https://vulners.com/securityvulns/SECURITYVULNS:VULN:9455"><table key="cpe:/a:openbsd:openssh:4.7p1">
<table>
<elem key="id">SSV:78173</elem>
<elem key="cvss">7.8</elem>
<elem key="is_exploit">true</elem>
<elem key="type">seebug</elem>
</table>
<table>
<elem key="id">SSV:69983</elem>
<elem key="cvss">7.8</elem>
<elem key="is_exploit">true</elem>
<elem key="type">seebug</elem>
</table>
<table>
<elem key="id">EDB-ID:24450</elem>
<elem key="cvss">7.8</elem>
<elem key="is_exploit">true</elem>
<elem key="type">exploitdb</elem>
</table>
<table>
<elem key="id">EDB-ID:15215</elem>
<elem key="cvss">7.8</elem>
<elem key="is_exploit">true</elem>
<elem key="type">exploitdb</elem>
</table>
<table>
<elem key="id">SECURITYVULNS:VULN:8166</elem>
<elem key="cvss">7.5</elem>
<elem key="is_exploit">false</elem>
<elem key="type">securityvulns</elem>
</table>
<table>
<elem key="id">PRION:CVE-2010-4478</elem>
<elem key="cvss">7.5</elem>
<elem key="is_exploit">false</elem>
<elem key="type">prion</elem>
</table>
<table>
<elem key="id">CVE-2012-1577</elem>
<elem key="cvss">7.5</elem>
<elem key="is_exploit">false</elem>
<elem key="type">cve</elem>
</table>
<table>
<elem key="id">CVE-2010-4478</elem>
<elem key="cvss">7.5</elem>
<elem key="is_exploit">false</elem>
<elem key="type">cve</elem>
</table>
<table>
<elem key="id">SSV:20512</elem>
<elem key="cvss">7.2</elem>
<elem key="is_exploit">true</elem>
<elem key="type">seebug</elem>
</table>
<table>
<elem key="id">PRION:CVE-2011-1013</elem>
<elem key="cvss">7.2</elem>
<elem key="is_exploit">false</elem>
<elem key="type">prion</elem>
</table>
<table>
<elem key="id">PRION:CVE-2008-1657</elem>
<elem key="cvss">6.5</elem>
<elem key="is_exploit">false</elem>
<elem key="type">prion</elem>
</table>
<table>
<elem key="id">CVE-2008-1657</elem>
<elem key="cvss">6.5</elem>
<elem key="is_exploit">false</elem>
<elem key="type">cve</elem>
</table>
<table>
<elem key="id">SSV:60656</elem>
<elem key="cvss">5.0</elem>
<elem key="is_exploit">true</elem>
<elem key="type">seebug</elem>
</table>
<table>
<elem key="id">PRION:CVE-2011-2168</elem>
<elem key="cvss">5.0</elem>
<elem key="is_exploit">false</elem>
<elem key="type">prion</elem>
</table>
<table>
<elem key="id">PRION:CVE-2010-5107</elem>
<elem key="cvss">5.0</elem>
<elem key="is_exploit">false</elem>
<elem key="type">prion</elem>
</table>
<table>
<elem key="id">CVE-2010-5107</elem>
<elem key="cvss">5.0</elem>
<elem key="is_exploit">false</elem>
<elem key="type">cve</elem>
</table>
<table>
<elem key="id">CVE-2010-4816</elem>
<elem key="cvss">5.0</elem>
<elem key="is_exploit">false</elem>
<elem key="type">cve</elem>
</table>
<table>
<elem key="id">PRION:CVE-2010-4755</elem>
<elem key="cvss">4.0</elem>
<elem key="is_exploit">false</elem>
<elem key="type">prion</elem>
</table>
<table>
<elem key="id">PRION:CVE-2010-4754</elem>
<elem key="cvss">4.0</elem>
<elem key="is_exploit">false</elem>
<elem key="type">prion</elem>
</table>
<table>
<elem key="id">PRION:CVE-2012-0814</elem>
<elem key="cvss">3.5</elem>
<elem key="is_exploit">false</elem>
<elem key="type">prion</elem>
</table>
<table>
<elem key="id">PRION:CVE-2011-5000</elem>
<elem key="cvss">3.5</elem>
<elem key="is_exploit">false</elem>
<elem key="type">prion</elem>
</table>
<table>
<elem key="id">CVE-2023-51767</elem>
<elem key="cvss">3.5</elem>
<elem key="is_exploit">false</elem>
<elem key="type">cve</elem>
</table>
<table>
<elem key="id">CVE-2012-0814</elem>
<elem key="cvss">3.5</elem>
<elem key="is_exploit">false</elem>
<elem key="type">cve</elem>
</table>
<table>
<elem key="id">CVE-2011-5000</elem>
<elem key="cvss">3.5</elem>
<elem key="is_exploit">false</elem>
<elem key="type">cve</elem>
</table>
<table>
<elem key="id">PRION:CVE-2011-4327</elem>
<elem key="cvss">2.1</elem>
<elem key="is_exploit">false</elem>
<elem key="type">prion</elem>
</table>
<table>
<elem key="id">CVE-2011-4327</elem>
<elem key="cvss">2.1</elem>
<elem key="is_exploit">false</elem>
<elem key="type">cve</elem>
</table>
<table>
<elem key="id">PRION:CVE-2008-3259</elem>
<elem key="cvss">1.2</elem>
<elem key="is_exploit">false</elem>
<elem key="type">prion</elem>
</table>
<table>
<elem key="id">CVE-2008-3259</elem>
<elem key="cvss">1.2</elem>
<elem key="is_exploit">false</elem>
<elem key="type">cve</elem>
</table>
<table>
<elem key="id">SECURITYVULNS:VULN:9455</elem>
<elem key="cvss">0.0</elem>
<elem key="is_exploit">false</elem>
<elem key="type">securityvulns</elem>
</table>
</table>
</script></port>
</ports>
<times srtt="1339" rttvar="3889" to="100000"/>
</host>
<runstats><finished time="1715023100" timestr="Mon May  6 21:18:20 2024" summary="Nmap done at Mon May  6 21:18:20 2024; 1 IP address (1 host up) scanned in 2.27 seconds" elapsed="2.27" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
    """

    # Parse XML data
    vulnerabilities = parse_xml(xml_data)

    # Create PyQt5 application
    app = QApplication(sys.argv)
    mainWindow = VulnerabilityTable(vulnerabilities)
    mainWindow.show()
    sys.exit(app.exec_())
