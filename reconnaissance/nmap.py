import subprocess

class Nmap:

def run_cmd(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        return output
    except subprocess.CalledProcessError as e:
        return e.output

# Example command
nmap_path = r"tools\nmap\nmap.exe"  # Path to nmap.exe
command = f'"{nmap_path}" -sn 192.168.1.0-253'  # Construct the command string

# Run the command and capture the output
result = run_cmd(command)

# Filter the result
filtered_result = [line.strip() for line in result.split('\n') if line.startswith(('Nmap scan', 'Host', 'MAC Address'))]

# Create a dictionary to store the information
hosts = {}
current_host = None

# Iterate through the filtered lines
for line in filtered_result:
    if line.startswith('Nmap scan report'):
        # If it's a new host, update the current_host variable
        current_host = line.split('for ')[1]
        hosts[current_host] = {}
    elif ':' in line:
        # If the line contains a ':', split it and add it to the dictionary
        key, value = line.split(': ', 1)
        hosts[current_host][key] = value
    else:
        # If the line doesn't contain a ':', add it as a new key with an empty value
        key = line
        hosts[current_host][key] = ""

# Print the dictionary
for host, info in hosts.items():
    print(f"Host: {host}")
    for key, value in info.items():
        print(f"{key}: {value}")
    print()
