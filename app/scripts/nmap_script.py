from qemu_script import QemuSSHManager

# Create an instance of QemuSSHManager
ssh_manager = QemuSSHManager()

command_to_execute = "nmap -A 192.168.1.254"
completion_indicator = "command completed"

print("Executing Nmap scan...")
for line in ssh_manager.execute_command_live(command_to_execute):
    print(line)
    if line.strip('\n') == completion_indicator:
        break

# Close the SSH connection
ssh_manager.close_connection()