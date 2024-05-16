import subprocess
import paramiko
import os

class QemuManager:
    def __init__(self) -> None:
        self.qemu_process = None

    def prep_kali(self):

        # SSH connection parameters
        ssh_host = '127.0.0.1'  # Host where QEMU is running
        ssh_port = 60022  # Port forwarded by QEMU for SSH (from host to guest)
        ssh_user = 'kali'  # Username for SSH login
        ssh_password = 'root'  # Password for SSH login

        # SSH connection
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(hostname=ssh_host, port=ssh_port, username=ssh_user, password=ssh_password)

        # Remet l'heure et la date à jour via SSH
        stdin, stdout, stderr = self.ssh.exec_command('sudo ntpdate -u pool.ntp.org')

        # Print the output
        print(stdout.read().decode())

        stdin, stdout, stderr = self.ssh.exec_command('sudo chmod 662 /var/run/gvmd/gvmd.sock')

        # Close SSH connection
        self.ssh.close()

        # Wait for user input before terminating QEMU
        #input("Press Enter to terminate QEMU...")

class QemuSSHManager:
    def __init__(self):
        self.host = '127.0.0.1'
        self.port = 60022
        self.username = 'kali'
        self.password = 'root'
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        

    def execute_command_live(self, command):
            self.ssh.connect(hostname=self.host, port=self.port, username=self.username, password=self.password)
            command_with_completion = f"{command} && echo 'command completed'"
            stdin, stdout, stderr = self.ssh.exec_command(command_with_completion)
            for line in stdout:
                stripped_line = line.strip('\n')
                if stripped_line == 'command completed':
                    continue  # Skip the line if it's "command completed"
                yield stripped_line
            self.ssh.close()  # Close SSH connection here