import socket
import nmap
from scapy.all import ARP, Ether, srp
from tkinter import *
from tkinter import ttk, messagebox  # Import de messagebox depuis tkinter
import customtkinter as ctk
from pythonping import ping
from threading import Thread  # Importer Thread depuis threading
import time

def afficher_latence():
    try:
        response_list = ping('8.8.8.8', size=40, count=10)
        latence_moyenne = response_list.rtt_avg_ms
        messagebox.showinfo("Latence", f"Latence moyenne : {latence_moyenne} ms")
    except Exception as e:
        messagebox.showerror("Erreur", f"Une erreur s'est produite : {e}")

def scan_ports(ip, ports='1-200'):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, arguments=f'-p {ports}')
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports.append(port)
    return open_ports

def scan_reseau(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []

    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    # Ajout de la vérification des ports ouverts
    for device in devices:
        open_ports = scan_ports(device['ip'])
        device['open_ports'] = open_ports

    return devices

def get_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return "N/A"  # Si le nom d'hôte n'est pas trouvé

def display_results(devices):
    # Effacer les entrées précédentes dans l'arbre
    for row in tree.get_children():
        tree.delete(row)

    # Ajouter les nouvelles entrées dans l'arbre
    for device in devices:
        hostname = get_hostname(device['ip'])
        tree.insert('', 'end', values=(hostname, device['ip'], device['mac'], ', '.join(map(str, device['open_ports']))))
    
    # Mettre à jour le nombre de machines connectées
    num_devices_value_label.configure(text=str(len(devices)))


def scan_button_clicked():
    ip_range = entry.get()
    devices = scan_reseau(ip_range)
    display_results(devices)

def update_num_devices():
    ip_range = '192.168.1.0/24'
    devices = scan_reseau(ip_range)
    num_devices_value_label.configure(text=str(len(devices)))

root = ctk.CTk()
root.title("Scanner de réseau")
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

label = ctk.CTkLabel(root, text="Entrez la plage d'adresses IP à scanner (format CIDR ex. 192.168.1.0/24):")
label.grid(row=0, column=0)

entry = ctk.CTkEntry(root)
entry.grid(row=0, column=1)

scan_button = ctk.CTkButton(root, text="Scanner", command=scan_button_clicked)
scan_button.grid(row=0, column=2)

tree = ttk.Treeview(root, columns=('Hostname', 'IP', 'MAC', 'Ports ouverts'), show='headings')
tree.heading('#1', text='Hostname')
tree.heading('#2', text='IP')
tree.heading('#3', text='MAC')
tree.heading('#4', text='Ports ouverts')
tree.column('#1', width=150)
tree.column('#2', width=150)
tree.column('#3', width=150)
tree.column('#4', width=150)
tree.grid(row=1, column=0, columnspan=3)

num_devices_label = ctk.CTkLabel(root, text="Nombre de machines connectées au réseau:")
num_devices_label.grid(row=2, column=0, padx=10, pady=5, sticky='w')

num_devices_value_label = ctk.CTkLabel(root, text="", width=10)
num_devices_value_label.grid(row=2, column=0, columnspan=3, padx=280, pady=0, sticky='w')

# Définir une variable globale pour stocker les derniers résultats du scan
last_scan_results = []

# Fonction pour afficher les derniers résultats du scan
def show_last_scan():
    if last_scan_results:
        display_results(last_scan_results)
    else:
        messagebox.showinfo("Aucun scan précédent", "Aucun résultat de scan précédent disponible.")

# Créer un bouton pour afficher les derniers résultats du scan dans la fenêtre principale
show_last_scan_button = ctk.CTkButton(root, text="Voir dernier scan", command=show_last_scan, width=2)
show_last_scan_button.grid(row=2, column=1, padx=20, pady=20)


import customtkinter

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

app = customtkinter.CTk()  # create window
app.title("SysOPS - GRP2")
app.geometry("400x240")

# Fonctions pour obtenir l'adresse IP locale et le nom de l'ordinateur
def get_local_ip():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

def get_computer_name():
    return socket.gethostname()

# Création des libellés pour l'adresse IP locale et le nom de l'ordinateur
ip_label = ctk.CTkLabel(app, text="Adresse IP locale:")
ip_label.grid(row=0, column=0, padx=10, pady=5, sticky=ctk.W)

computer_name_label = ctk.CTkLabel(app, text="Nom de l'ordinateur:")
computer_name_label.grid(row=1, column=0, padx=10, pady=5, sticky=ctk.W)

# Récupération des informations et affichage dans les libellés
ip_address = get_local_ip()
ip_value_label = ctk.CTkLabel(app, text=ip_address)
ip_value_label.grid(row=0, column=1, padx=10, pady=5, sticky=ctk.W)

computer_name = get_computer_name()
computer_name_value_label = ctk.CTkLabel(app, text=computer_name)
computer_name_value_label.grid(row=1, column=1, padx=10, pady=5, sticky=ctk.W)

# Créer un bouton pour tester la latence du WAN
wan_latency_button = ctk.CTkButton(app, text="Tester Latence WAN", command=afficher_latence)
wan_latency_button.grid(row=2, column=1, columnspan=2, pady=10)

def update_wan_latency():
    while True:
        try:
            response_list = ping('8.8.8.8', size=40, count=3)
            latence_moyenne = response_list.rtt_avg_ms
            latency_label.configure(text=f"Latence WAN : {latence_moyenne} ms")
        except Exception as e:
            latency_label.configure(text="Impossible de récupérer la latence WAN")
        time.sleep(10)

wan_latency_thread = Thread(target=update_wan_latency)
wan_latency_thread.daemon = True
wan_latency_thread.start()

# Afficher la latence du WAN
latency_label = ctk.CTkLabel(app, text="Latence WAN:")
latency_label.grid(row=3, column=0, padx=10, pady=5, sticky=ctk.W)

latency_value_label = ctk.CTkLabel(app, text="")
latency_value_label.grid(row=3, column=1, padx=5, pady=5, sticky=ctk.W)

# Ajout du bouton retour
return_button = ctk.CTkButton(root, text="Retour", command=lambda: (app.deiconify(), root.withdraw()))
return_button.grid(row=2, column=2, padx=10, pady=5, sticky='w')

# Version du logiciel
software_version = "Version 1.0"

# Créer un libellé pour afficher la version
version_label = ctk.CTkLabel(app, text=software_version)
version_label.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky=ctk.W)

# create button
button = ctk.CTkButton(app, text="Scanner-Réseau", command=lambda: (root.deiconify(), app.withdraw()))
button.grid(row=2, column=0, padx=20, pady=20)

# Lancer la boucle principale de l'interface graphique
app.mainloop()
root.mainloop()