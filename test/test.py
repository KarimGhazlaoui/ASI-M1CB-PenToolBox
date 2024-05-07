import xml.etree.ElementTree as ET

def extract_hosts_info(xml_content):
    hosts_info = []
    
    # Parse XML
    root = ET.fromstring(xml_content.strip())
    
    # Iterate over host elements
    for host in root.findall('host'):
        host_info = {}
        
        # Extract address information
        address_elem = host.find('address')
        if address_elem is not None:
            host_info['address'] = address_elem.attrib.get('addr', 'aucun')
        else:
            host_info['address'] = 'aucun'
        
        # Extract status information
        status_elem = host.find('status')
        if status_elem is not None:
            host_info['status'] = status_elem.attrib.get('state', 'aucun')
        else:
            host_info['status'] = 'aucun'
        
        # Extract hostname information
        hostnames_elem = host.find('hostnames')
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find('hostname')
            if hostname_elem is not None:
                host_info['hostname'] = hostname_elem.attrib.get('name', 'aucun')
            else:
                host_info['hostname'] = 'aucun'
        else:
            host_info['hostname'] = 'aucun'
        
        hosts_info.append(host_info)
    
    return hosts_info

# Example usage
xml_content = '''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.94SVN scan initiated Mon May  6 18:19:13 2024 as: nmap -sn -oX - 192.168.1.0/24 -->
<nmaprun scanner="nmap" args="nmap -sn -oX - 192.168.1.0/24" start="1715012353" startstr="Mon May  6 18:19:13 2024" version="7.94SVN" xmloutputversion="1.05">
<verbose level="0"/>
<debugging level="0"/>
<host><status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="192.168.1.2" addrtype="ipv4"/>
<hostnames>
</hostnames>
<times srtt="31974" rttvar="35328" to="173286"/>
</host>
<host><status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="192.168.1.160" addrtype="ipv4"/>
<hostnames>
<hostname name="pi.hole" type="PTR"/>
</hostnames>
<times srtt="2183" rttvar="4040" to="100000"/>
</host>
<host><status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="192.168.1.195" addrtype="ipv4"/>
<hostnames>
</hostnames>
<times srtt="34213" rttvar="34213" to="171065"/>
</host>
<host><status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="192.168.1.254" addrtype="ipv4"/>
<hostnames>
</hostnames>
<times srtt="1247" rttvar="5000" to="100000"/>
</host>
<runstats><finished time="1715012357" timestr="Mon May  6 18:19:17 2024" summary="Nmap done at Mon May  6 18:19:17 2024; 256 IP addresses (4 hosts up) scanned in 3.51 seconds" elapsed="3.51" exit="success"/><hosts up="4" down="252" total="256"/>
</runstats>
</nmaprun>
'''.strip()  # Strip leading and trailing whitespace
hosts_info = extract_hosts_info(xml_content)
for host_info in hosts_info:
    print("Address:", host_info['address'])
    print("Status:", host_info['status'])
    print("Hostname:", host_info['hostname'])
    print()
