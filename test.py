import paramiko
import subprocess
import re

def ssh_connect(hostname, port, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, port=port, username=username, password=password)
        return client
    except paramiko.AuthenticationException:
        print("Authentication failed, please verify your credentials.")
        return None
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection: {e}")
        return None

def nmap_scan_hosts(subnet):
    try:
        command = f"nmap -sn {subnet}"
        result = subprocess.run(command.split(), capture_output=True, text=True)
        print("Hosts Output:")
        print(result.stdout)  # Print the output of the nmap command
        return result.stdout
    except Exception as e:
        print(f"Error scanning for hosts: {e}")

def nmap_scan_open_ports(hosts_up):
    try:
        command = f"nmap -p 1-65535 -T4 -oN open_ports.txt {hosts_up}"
        result = subprocess.run(command.split(), capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error scanning for open ports: {e}")

def nmap_scan_os_info(hosts_up):
    try:
        command = f"nmap -O -oN os_info.txt {hosts_up}"
        result = subprocess.run(command.split(), capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error scanning for OS information: {e}")

def nmap_scan_cve(hosts_up):
    try:
        command = f"nmap --script vulners --script-args mincvss=7.0 -oN cve_scan.txt {hosts_up}"
        result = subprocess.run(command.split(), capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error scanning for CVEs: {e}")

def main():
    # SSH connection details
    hostname = "localhost"
    port = 60022
    username = "kali"
    password = "root"
    subnet = "192.168.1.0/24"  # Correct subnet

    # Connect to SSH
    client = ssh_connect(hostname, port, username, password)
    if client:
        print("SSH connection established successfully.")
        
        # Step 1: Scan for hosts
        print("Scanning for hosts...")
        hosts_output = nmap_scan_hosts(subnet)
        
        if hosts_output:
            # Print the full hosts output for better understanding
            print("Full Hosts Output:")
            print(hosts_output)
            
            # Extract hosts up
            hosts_up = re.findall(r'(\d+\.\d+\.\d+\.\d+)', hosts_output)
            
            print("Hosts Up:", hosts_up)
            
            if hosts_up:
                # Step 2: Scan for open ports
                print("Scanning for open ports...")
                open_ports_output = nmap_scan_open_ports(" ".join(hosts_up))
                print(open_ports_output)  # Print the output of the open ports scan
                
                # Step 3: Scan for OS information
                print("Scanning for OS information...")
                os_info_output = nmap_scan_os_info(" ".join(hosts_up))
                print(os_info_output)  # Print the output of the OS information scan
                
                # Step 4: Scan for CVEs
                print("Scanning for CVEs...")
                cve_output = nmap_scan_cve(" ".join(hosts_up))
                print(cve_output)  # Print the output of the CVE scan
            else:
                print("No hosts are up.")
                
            # Close SSH connection
            client.close()
            print("SSH connection closed.")


if __name__ == "__main__":
    main()
