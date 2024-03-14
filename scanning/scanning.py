import tkinter as tk
from tkinter import ttk
import customtkinter
import re
import main.reconnaissance.nmap as nmap

class NmapScannerApp:
    def __init__(self, parent):

        self.parent = parent
        self.tree = None

        self.middle_frame = customtkinter.CTkFrame(parent, width=300, corner_radius=0)
        self.middle_frame.grid(row=0, column=1, rowspan=4, sticky="nsew")
        self.middle_frame.grid_rowconfigure(7, weight=1)

        self.title_scan = customtkinter.CTkLabel(self.middle_frame, text="SCANNING", font=("arial", 20))
        self.title_scan.grid(row=0, column=0, sticky="nsew")
        
        # Create a Frame inside the parent for the CTkTabview
        self.parent_frame = tk.Frame(self.middle_frame, background="#242424")
        self.parent_frame.grid(row=1, column=0, sticky="nsew")

        self.tabview = customtkinter.CTkTabview(self.parent_frame) 
        self.tabview.grid(row=0, column=1, rowspan=4, sticky="nsew")
        self.tabview.add("Options du Scan")

        # Choix du scan
        self.radiobutton_frame = customtkinter.CTkFrame(self.tabview.tab("Options du Scan"))
        self.radiobutton_frame.grid(row=0, column=0, padx=(20, 20), pady=(20, 0), sticky="nsw")
        self.radio_var = tk.IntVar(value=0)
        self.label_radio_group = customtkinter.CTkLabel(master=self.radiobutton_frame, text="Mode du scan :")
        self.label_radio_group.grid(row=0, column=2, columnspan=1, padx=10, pady=10, sticky="")
        self.radio_button_1 = customtkinter.CTkRadioButton(master=self.radiobutton_frame, variable=self.radio_var, value=0, text="Furtif")
        self.radio_button_1.grid(row=0, column=3, pady=10, padx=20, sticky="n")
        self.radio_button_2 = customtkinter.CTkRadioButton(master=self.radiobutton_frame, variable=self.radio_var, value=1, text="Agressif")
        self.radio_button_2.grid(row=0, column=4, pady=10, padx=20, sticky="n")
    
        # Input pour indiquer le réseau à scan
        self.label_subnet = customtkinter.CTkLabel(self.tabview.tab("Options du Scan"), text="Sous-Réseau à scanner (XXX.XXX.XXX.XXX/XX):")
        self.label_subnet.grid(row=1, column=0, padx=20, pady=10)

        self.options_subnet = customtkinter.CTkEntry(self.tabview.tab("Options du Scan"), width=425, placeholder_text="Saisissez un sous-réseau ou laissez vide pour scanner le réseau actuel.")
        self.options_subnet.grid(row=1, column=1, padx=20, pady=10) 

        # Bouton pour lancer le scan
        self.options_launchscan_button = customtkinter.CTkButton(self.tabview.tab("Options du Scan"), command=self.scan, text="Lancer le scan")
        self.options_launchscan_button.grid(row=2, column=0, padx=20, pady=10)
    
    def scan(self):

        subnet = self.options_subnet.get()
        scanchoix = self.radio_var.get()

        try:
            self.tabview.delete("Endpoint Détecté")
        except ValueError:
            pass

        try:
            self.tabview.delete("Ports Détecté")
        except ValueError:
            pass

        if scanchoix == 0:
            argscan = "-sn -PE -PP -PS21,22,23,25,80,113,31339 -PA80,113,443,10042 --data-length 36 --randomize-hosts"
        else:
            argscan = "-T5 -sn"        
        
        if not subnet :
            print("vide")
            target_network = nmap.get_network_interface_info()
            target_network = target_network[0] + "/" + target_network[1]
            result = nmap.scan(argscan + " " + target_network)
            print(argscan + " " + target_network)
            hosts = self.parse_nmap_output(result)
            self.tabview.add("Endpoint Détecté")
            self.tabview.add("Ports Détecté")
            self.tabview.tab("Endpoint Détecté").grid_columnconfigure(0, weight=1)
            self.tabview.set("Endpoint Détecté")
            self.create_tree(hosts)
        else:
            print(subnet)
            result = nmap.scan(subnet)
            hosts = self.parse_nmap_output(result)
            self.tabview.add("Endpoint Détecté")
            self.tabview.add("Ports Détecté")
            self.tabview.tab("Endpoint Détecté").grid_columnconfigure(0, weight=1)
            self.tabview.set("Endpoint Détecté")
            self.create_tree(hosts)

    def create_tree(self, hosts):
        # Create a frame to contain the tree
        self.tree_frame = tk.Frame(self.tabview.tab("Endpoint Détecté"))
        self.tree_frame.grid(row=0, column=0, sticky="nsew")

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="silver", foreground="black", fieldbackground="silver")

        style.map('Treeview', background=[('selected', 'green')])

        columns = ["Host IP", "Status", "Latency", "MAC Address", "Manufacturer"]
        self.tree = ttk.Treeview(self.tree_frame, columns=columns, show='headings')
        self.tree.grid(row=0, column=0, sticky="nsew")

        self.scrollbar = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.config(yscrollcommand=self.scrollbar.set)

        for col in columns:
            self.tree.heading(col, text=col, anchor='center')
            self.tree.column(col, anchor='center')

        for i in hosts:
            self.tree.insert('', 'end', values=i)


    def parse_nmap_output(self, output):
        hosts = []
        pattern = r'Nmap scan report for (\S+)\s*Host is (\w+)\s*\((.*?)\).*?MAC Address: ([\w:]+)\s*(?:\((.*?)\))?'
        matches = re.findall(pattern, output, re.DOTALL)

        for match in matches:
            ip = match[0]
            status = match[1]
            latency = match[2]
            mac_address = match[3]
            manufacturer = match[4].strip() if match[4] else "Unknown"
            hosts.append((ip, status, latency, mac_address, manufacturer))

        return hosts
