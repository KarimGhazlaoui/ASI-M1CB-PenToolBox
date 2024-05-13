import subprocess
import threading
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
                '-nic', 'user,restrict=off,model=virtio,id=vmnic,hostfwd=tcp::60022-:22,hostfwd=tcp::9392-:9392',
                '-monitor', 'stdio',
                '-vga',  'vmware',
                '-loadvm', 'gvm',
                '-vnc', ':0'
            ]

            # Start QEMU in a separate thread
            self.qemu_thread = threading.Thread(target=self._start_qemu_thread, args=(qemu_command,))
            self.qemu_thread.start()

    def _start_qemu_thread(self, qemu_command):
        # Start QEMU
        self.qemu_process = subprocess.Popen(qemu_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Wait for QEMU to boot (you may need to adjust the sleep duration)

    def terminate_qemu(self):
        # Terminate QEMU process
        self.qemu_process.terminate()

        # Wait for the QEMU thread to join (wait for it to finish)
        self.qemu_thread.join()

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