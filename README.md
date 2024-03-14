# Scanner de Réseau

  

Ce programme est conçu pour scanner les appareils connectés à un réseau local et afficher leurs informations pertinentes telles que le nom d'hôte, l'adresse IP, l'adresse MAC et les ports ouverts.

  

## Installation

  

1. Assurez-vous d'avoir Python installé sur votre système. Si ce n'est pas le cas, vous pouvez le télécharger depuis le site officiel de Python.

2. Clonez ou téléchargez le code source de ce projet sur votre machine.

3. Installez les dépendances en exécutant la commande suivante dans votre terminal :

    `pip install pythonping scapy python-nmap`

  

## Utilisation

  

1. Exécutez le programme en exécutant le fichier `main.py` avec Python :

    `python app_scan_deo.py`

2. Entrez la plage d'adresses IP à scanner au format CIDR (par exemple, `192.168.1.0/24`) dans la zone de saisie prévue.

3. Cliquez sur le bouton "Scanner" pour démarrer le scan du réseau.

4. Les appareils détectés seront affichés dans un tableau, avec leurs informations telles que le nom d'hôte, l'adresse IP, l'adresse MAC et les ports ouverts.

5. Vous pouvez également afficher la latence du réseau WAN en cliquant sur le bouton "Tester Latence WAN".

  

## Fonctionnalités supplémentaires

  

- Affichage de la latence moyenne du réseau WAN.

- Possibilité de visualiser les résultats du dernier scan.

- Intégration d'une interface graphique conviviale avec la possibilité de basculer entre le scanner de réseau et d'autres fonctionnalités.