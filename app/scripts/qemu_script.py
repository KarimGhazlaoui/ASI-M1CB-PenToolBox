import subprocess
import paramiko
import time

class QemuManager:
    def __init__(self) -> None:
        pass

    def start_qemu(self):
        # Define QEMU command with monitor enabled
        qemu_command = [
            r'app\qemu\qemu-system-x86_64.exe',  # Path to QEMU executable
            '-m',  '8G',
            '-smp', '4',
            '-hda', r'app\qemu\kali\kali.qcow2',
            '-usbdevice', 'tablet',
            '-name', 'kali',
            '-nic', 'user,id=vmnic,hostfwd=tcp::60022-:22,hostfwd=tcp::9392-:9392',
            '-monitor', 'stdio',
            '-loadvm', 'gvm',
            '-vnc', ':0'
        ]

        # Start QEMU
        self.qemu_process = subprocess.Popen(qemu_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Wait for QEMU to boot (you may need to adjust the sleep duration)
        time.sleep(10)

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

        # Close SSH connection
        self.ssh.close()

        # Wait for user input before terminating QEMU
        #input("Press Enter to terminate QEMU...")

    def terminate_qemu(self):
        #Terminate QEMU process
        self.qemu_process.terminate()

class QemuSSHManager:
    def __init__(self):
        self.host = '127.0.0.1'
        self.port = 60022
        self.username = 'kali'
        self.password = 'root'
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(hostname=self.host, port=self.port, username=self.username, password=self.password)

    def execute_command_live(self, command):
            command_with_completion = f"{command} && echo 'command completed'"
            stdin, stdout, stderr = self.ssh.exec_command(command_with_completion)
            for line in stdout:
                yield line.strip('\n')
                if line.strip('\n') == 'command completed':
                    break

    def close_connection(self):
        self.ssh.close()