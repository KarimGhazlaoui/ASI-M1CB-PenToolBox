# coding:utf-8
import sys
import paramiko
import time
import xml.etree.ElementTree as ET

from PyQt5.QtCore import QObject, Qt, QThread, pyqtSignal, QSize, QTimer
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QWidget, QMessageBox

from qfluentwidgets import SplitFluentWindow, FluentIcon, Flyout, InfoBarIcon, FlyoutAnimationType, MessageBox, NavigationItemPosition, SplashScreen

from app.interface.scan_interface import ScanInterface
from app.interface.engagement_interface import EngagementInterface
from app.interface.cible_interface import CibleInterface
from app.interface.vulnerabilite_interface import VulnerabiliteInterface
from app.interface.evaluation_interface import EvaluationInterface
from app.interface.qemu_interface import QemuInterface

from app.scripts.qemu_script import QemuManager
from app.engagement import CustomMessageBox
from app.scripts.profile_script import Profile
from app.scripts.gvm_script import gvm
from app.scripts.rapport_script import RapportGenerateur
from app.automatisation import scan_vers_cible
from app.scripts.qemu_script import QemuManager

import app.resource.resource_rc

# Classe Worker pour effectuer des tâches longues en arrière-plan
class Worker(QThread):
    finished = pyqtSignal()  # Signal émis lorsque la tâche est terminée
    result = pyqtSignal(object)  # Signal émis avec le résultat de la tâche

    def __init__(self, function, *args, **kwargs):
        super().__init__()
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.stopped = False

    def stop(self):
        self.stopped = True

    def run(self):
        if not self.stopped:
            result = self.function(*self.args, **self.kwargs)
            self.result.emit(result)  # Émettre le résultat
        self.finished.emit()  # Émettre le signal de fin

# Classe SSHWorker pour exécuter des commandes SSH en arrière-plan
class SSHWorker(QThread):
    update_signal = pyqtSignal(str)  # Signal pour envoyer des mises à jour à l'interface graphique
    finished_signal = pyqtSignal()  # Signal émis lorsque la tâche SSH est terminée

    def __init__(self, host='127.0.0.1', port=60022, username='kali', password='root', command=None):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.command = command + ' && echo "command completed"'
        self.output = ""  # Attribut pour stocker la sortie de la commande

    def run(self):
        print("démarrage run worker")
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, self.port, username=self.username, password=self.password)
            stdin, stdout, stderr = client.exec_command(self.command)
            for line in stdout:
                output_line = line.strip()
                self.update_signal.emit(output_line)
                self.output += output_line + "\n"  # Ajouter la sortie à l'attribut
            for line in stderr:
                output_line = line.strip()
                self.update_signal.emit(output_line)
                self.output += output_line + "\n"  # Ajouter la sortie à l'attribut
            while not stdout.channel.exit_status_ready():
                pass
            self.finished_signal.emit()  # Émettre le signal de fin
            client.close()
        except Exception as e:
            error_message = f"Erreur : {str(e)}"
            self.update_signal.emit(error_message)
            self.output += error_message + "\n"  # Ajouter le message d'erreur à l'attribut

# Classe principale
class main(SplitFluentWindow):

    automatisation = scan_vers_cible()
    global_taskid = ""
    global_rapportid = "31f31539-c738-4a0a-9493-b784bb5ce16a"

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.gvm_management = gvm(self)

        self.worker = None
        
        #CustomMessageBox(self)

        # Localisation des profiles d'entreprises
        self.profile_manager = Profile('app/profiles')

        self.initWindow()

        # Création des sous-interface
        self.scanInterface = ScanInterface(self)
        #self.engagementInterface = EngagementInterface(self)
        self.cibleInterface = CibleInterface(self)
        self.vulnerabiliteInterface = VulnerabiliteInterface(self)
        self.evaluationInterface = EvaluationInterface(self)
        self.qemuInterface = QemuInterface(self)

        pos = NavigationItemPosition.SCROLL

        self.initNavigation()
        self.splashScreen.finish()

    # Creation des interfaces
    def initNavigation(self):

        # Ajout des sous-interfaces à la fenêtre principale
        self.addSubInterface(self.scanInterface, QIcon(":/images/scaninterfaceicon.png"), 'Scan - Cible et Reconnaissance')
        self.addSubInterface(self.cibleInterface, QIcon(":/images/cible.png"), 'Scan - Cibles Détectées')
        self.addSubInterface(self.vulnerabiliteInterface, QIcon(":/images/vulnerabilite.png"), 'Exploitation - Vulnérabilités')
        self.addSubInterface(self.evaluationInterface, QIcon(":/images/strike.png"), 'Exploitation - Evaluation des Vulnérabilités')
        self.navigationInterface.addSeparator()
        self.addSubInterface(self.qemuInterface, QIcon(":/images/kali.png"), 'Kali - Control Center')

        # Ajout d'un élément de navigation pour générer un rapport
        self.navigationInterface.addItem(
            routeKey='price',
            icon=QIcon(":/images/agreement.png"),
            text="Générer un Rapport",
            onClick=self.ReportCreator,
            selectable=False,
            tooltip="Génère un rapport",
            position=NavigationItemPosition.BOTTOM
        )

        # Connexion des signaux aux slots
        self.scanInterface.boutonprofilecreation.clicked.connect(self.profiles_creation)
        self.scanInterface.chargementprofile.clicked.connect(self.chargement_profile)
        self.scanInterface.lancementscan.clicked.connect(self.lancer_scan)
        self.cibleInterface.scanvulnerabilite.clicked.connect(self.vulnerabilite_scan)
        self.vulnerabiliteInterface.scanvulnerabilite.clicked.connect(self.evaluation_transition)

        self.evaluationInterface.passwordchecker.textChanged.connect(self.check_strength)
        self.evaluationInterface.hydraexecution.clicked.connect(self.hydra_lancement)

        self.profiles_initialisation()
        self.vulnerabilite_traitement_start()

    # Splash Screen démarrage
    def initWindow(self):
        # Préparation paramètre fenêtre PyQt5
        self.resize(1280, 800)
        self.setWindowTitle("KGB - PenToolBox")
        self.setWindowIcon(QIcon(':/images/logo.png'))

        # create splash screen
        self.splashScreen = SplashScreen(self.windowIcon(), self)
        self.splashScreen.setIconSize(QSize(106, 106))
        self.splashScreen.raise_()

        desktop = QApplication.desktop().availableGeometry()
        w, h = desktop.width(), desktop.height()
        self.move(w//2 - self.width()//2, h//2 - self.height()//2)
        self.show()
        # Intégration QemuManager        
        self.qemu_manager = QemuManager()
        self.qemu_manager.start_qemu()
        #time.sleep(5)
        self.qemu_manager = QemuManager()
        self.qemu_manager.prep_kali()
        QApplication.processEvents()

    def resizeEvent(self, e):
        super().resizeEvent(e)
        if hasattr(self, 'splashScreen'):
            self.splashScreen.resize(self.size())

    # Fonction pour initialiser les profils
    def profiles_initialisation(self):
        print("Initialisation des profils")
        profiles = self.profile_manager.list_profiles()
        self.scanInterface.loadprofile.clear()
        if profiles:
            self.scanInterface.loadprofile.addItems(profiles)

    # Fonction pour créer un profil
    def profiles_creation(self):
        print("Création du profil")
        profile = self.scanInterface.createprofile.text()

        if not profile:
            print("Aucun texte entré")
            return
        if profile in self.profile_manager.list_profiles():
            print("Profil déjà existant")
            return
        
        variables = {}
        self.profile_manager.save_profile(variables,profile)
        self.profiles_initialisation()
        print("Profil créé avec succès")

    # Fonction pour charger un profil
    def chargement_profile(self):
        print("Chargement du profil")
        selected_profile = self.scanInterface.loadprofile.currentText()
        if selected_profile:
            self.scanInterface.actualprofile.setText(selected_profile)

            # Partie cible sous-réseau
            reseau_cible = self.profile_manager.load_variable(selected_profile, "reseau_cible")
            if reseau_cible is not None:
                self.scanInterface.sousreseau.setText(str(reseau_cible))
            else:
                self.scanInterface.sousreseau.clear()

            # Partie cibles détectées
            cible_detecte = self.profile_manager.load_variable(selected_profile, "cible_detecte")
            if cible_detecte is not None:
                self.cibleInterface.cibletable(scan_results=cible_detecte)
            else:
                self.cibleInterface.cibledetecte.clear()

            # Partie vulnérabilités détectées
            vulnerabilite_detecte = self.profile_manager.load_variable(selected_profile, "vulnerabilite_detecte")
            if vulnerabilite_detecte is not None:
                self.vulnerabiliteInterface.chargement_vulnerabilite(vulnerabilite_results=vulnerabilite_detecte)
            else:
                self.vulnerabiliteInterface.clear_vulnerabilite()

            # Chargement des cibles Hydra si disponibles
            cible_21 = set()
            vulnerabilite_cible = self.profile_manager.load_variable(selected_profile, "vulnerabilite_detecte")

            if vulnerabilite_cible is not None:
                for item in vulnerabilite_cible:
                    if item['Port'] == '21':
                        cible_21.add(item['IP'])
            else:
                cible_21 = []
            
            hydra_cibles = list(cible_21)
            self.evaluationInterface.hydracomboboxtarget.clear()
            self.evaluationInterface.hydracomboboxtarget.addItems(hydra_cibles)

        else:
            print("Aucun profil sélectionné")

    # Fonction pour générer un rapport
    def ReportCreator(self):
        selected_profile = self.scanInterface.actualprofile.text()
        generer_pdf = RapportGenerateur(Profile)
        if selected_profile:
            generer_pdf.GenererRapport(Profile=selected_profile)
        else:
            print("Aucun profil")

    # Fonction pour lancer un scan
    def lancer_scan(self):
        if self.scanInterface.actualprofile.text():
            selected_profile = self.scanInterface.loadprofile.currentText()
            cible = self.scanInterface.sousreseau.text()

            self.worker = Worker(self.automatisation.lancement_scan, sousreseau=cible, optionscan=1)
            self.worker.result.connect(lambda result, cible=cible: self.scan_finished(selected_profile, cible, result))
            self.worker.finished.connect(self.worker.deleteLater)

            self.worker.start()
        else:
            self.infofly(icone=InfoBarIcon.ERROR,titre="Aucun profil sélectionné",contenu="Merci de charger ou créer un profil",cible=self.scanInterface.lancementscan)
            print("Aucun profil sélectionné ou chargé")

    # Fonction appelée lorsque le scan est terminé
    def scan_finished(self, selected_profile, cibles, result):
        if result:   
            self.profile_manager.add_or_update_variable(selected_profile, "reseau_cible", cibles)
        else:
            ip_address, cidr = self.automatisation.get_network_interface_info()
            result = ip_address + "/" + cidr
            self.profile_manager.add_or_update_variable(selected_profile, "reseau_cible", cibles)
        
        # Mettre à jour les cibles détectées dans le profil
        self.profile_manager.add_or_update_variable(selected_profile, "cible_detecte", result)

        print(result)

        self.scanInterface.sousreseau.setText(str(cibles))

        # Mettre à jour l'interface avec les résultats du scan
        self.cibleInterface.cibletable(scan_results=result)

        # Passer à l'interface des cibles après le traitement des résultats du scan
        SplitFluentWindow.switchTo(self, interface=self.cibleInterface)

    # Fonction pour scanner les vulnérabilités
    def vulnerabilite_scan(self):
        cible_table = self.cibleInterface.TableContents()
        if cible_table:
            print("table vulnerabilite test")
            print(cible_table)
            vulnerabilite = self.gvm_management.scan_vulnerabilite(cible_table)
            print(vulnerabilite)
            #SplitFluentWindow.switchTo(self, interface=self.vulnerabiliteInterface)
        else:
            self.infofly(icone=InfoBarIcon.ERROR, titre="Aucune cible disponible", contenu="Aucune cible n'existe, effectuer un scan au préalable", cible=self.cibleInterface.scanvulnerabilite)

    # Fonction appelée lorsque le scan des vulnérabilités est terminé
    def vulnerabilite_scan_finished(self, vulnerabilite):
        # Traiter le résultat du scan de vulnérabilités
        print("Résultat du scan de vulnérabilité:", vulnerabilite)
        # Mettre à jour l'interface avec les résultats du scan de vulnérabilités
        self.vulnerabiliteInterface.update_vulnerabilities(vulnerabilite)
        # Passer à l'interface de vulnérabilités après le traitement des résultats du scan
        SplitFluentWindow.switchTo(self, interface=self.vulnerabiliteInterface)

    # Fonction pour afficher le contenu de la table
    def printtable(self):
        cible_table = self.cibleInterface.TableContents()
        print(cible_table)

    # Fonction pour créer la tâche GVM
    def gvm_creation(self, commandssh=None, callback=None):
        if commandssh is not None:
            print("gvm_creation, contenu commandssh :", commandssh)
            self.worker = SSHWorker(command=commandssh)
            self.worker.update_signal.connect(self.cibleInterface.vulnerabilitelive.append)
            self.worker.finished_signal.connect(lambda: self.gvm_fin(callback))  # Se connecter au slot pour la fin
            self.worker.start()
        else:
            print("GVM : Commande vide, problème au niveau de la fonction gvm_creation")

    # Fonction appelée à la fin de Hydra
    def gvm_fin(self, callback):
        gvm_resultat = self.worker.output  # Accéder à l'attribut de sortie
        selected_profile = self.scanInterface.loadprofile.currentText()
        self.profile_manager.add_or_update_variable(selected_profile, "gvm_resultat", gvm_resultat)
        print("Sortie de la commande gvm :", gvm_resultat)
        if callback:
            callback(gvm_resultat)

    # Fonction pour mettre à jour en temps réel
    def liveupdate(self, livedata):
        self.cibleInterface.liveupdate(livedata)

    # Fonction pour vérifier le status du scan OpenVas
    def vulnerabilite_status(self, rapportid, taskid):
        print("vulnerabilite_status taskid :", taskid)
        print("vulnerabilite_status rapportid :", rapportid)
        self.global_rapportid = rapportid
        self.global_taskid = taskid
        livestatus = [self.global_taskid, 'Création', 0]
        self.cibleInterface.gvm_progress_table(liveprogress=livestatus)
        self.status = ""
        self.timer = QTimer()
        self.timer.timeout.connect(self.vulnerabilite_status_debut)

        self.timer.start(10000)

    def vulnerabilite_status_debut(self):
        print("global_taskid :", self.global_taskid)
        if self.global_taskid is not None:
            commandssh = f"""gvm-cli socket --xml '<get_tasks task_id="{self.global_taskid}"/>' --pretty"""
            self.worker = SSHWorker(command=commandssh)
            #self.worker.update_signal.connect(self.cibleInterface.vulnerabilitelive.append)
            self.worker.finished_signal.connect(self.vulnerabilite_status_fin)
            self.worker.start()

    def vulnerabilite_status_fin(self):
        self.gvm_management = gvm(self)
        reponse_status = self.worker.output
        print(reponse_status)
        lines = reponse_status.strip().split('\n')
        if lines[-1].strip() == 'command completed':
            lines.pop()
        reponse_status = '\n'.join(lines)

        self.status = self.gvm_management.status_live_update(response=reponse_status)
        print("retour status :", self.status)

        if self.status[0] == "Done":
            self.timer.stop()
            self.vulnerabilite_traitement_start

        livestatus = [self.global_taskid, self.status[0], self.status[1]]

        self.cibleInterface.gvm_progress_table(liveprogress=livestatus)

    def vulnerabilite_traitement_start(self):
        if self.global_rapportid is not None:
            commandssh = f"""gvm-cli socket --xml "<get_reports report_id='{self.global_rapportid}' details='True' sort-reverse='severity' format_id='c1645568-627a-11e3-a660-406186ea4fc5'/>" --pretty"""
            self.worker = SSHWorker(command=commandssh)
            self.worker.finished_signal.connect(self.vulnerabilite_traitement_fin)
            self.worker.start()

    def vulnerabilite_traitement_fin(self):
        self.gvm_management = gvm(self)
        rapport = self.worker.output
        lines = rapport.strip().split('\n')
        if lines[-1].strip() == 'command completed':
            lines.pop()
        rapport = '\n'.join(lines)

        rapport_clean = self.gvm_management.rapport_nettoyage(rapport)

        cve_csv = self.gvm_management.traitement_csv(donnee_csv=rapport_clean)

        # Sauvegarde dans le profile du résultat
        #selected_profile = self.scanInterface.loadprofile.currentText()
        #self.profile_manager.add_or_update_variable(selected_profile, "vulnerabilite_detecte", cve_csv)

        self.vulnerabiliteInterface.chargement_vulnerabilite(vulnerabilite_results=cve_csv)

    # Fonction pour transférer les cibles vers hydra
    def evaluation_transition(self):
        cible_21 = set()
        vulnerabilite_cible = []
        
        if self.vulnerabiliteInterface.vulnerabilitetable.rowCount() > 0:

            for row in range(self.vulnerabiliteInterface.vulnerabilitetable.rowCount()):
                row_data = []
                for column in range(self.vulnerabiliteInterface.vulnerabilitetable.columnCount()):
                    item = self.vulnerabiliteInterface.vulnerabilitetable.item(row, column)
                    if item is not None:
                        row_data.append(item.text())
                    else:
                        row_data.append("")  # Add empty string if cell is empty
                vulnerabilite_cible.append(row_data)

            for item in vulnerabilite_cible:
                if item[1] == '21':
                    cible_21.add(item[0])

            hydra_cibles = list(cible_21)
            self.evaluationInterface.hydracomboboxtarget.clear()
            self.evaluationInterface.hydracomboboxtarget.addItems(hydra_cibles)
        else:
            print("liste des vulnerabilites vide")
            self.infofly(icone=InfoBarIcon.ERROR, titre="Aucune vulnérabilité",contenu="Aucune vulnérabilité détecté, faite un scan de vulnérabilité avant d'effectuer une évaluation", cible=self.vulnerabiliteInterface.scanvulnerabilite)

    # Fonction pour vérifier la sécurité du mot de passe
    def check_strength(self):
        password = self.evaluationInterface.passwordchecker.text()
        self.evaluationInterface.complexitevisuel.setVisible(True)

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        if len(password) < 8 or not (has_upper and has_lower and has_digit and has_special):
            strength = "Faible"
            self.evaluationInterface.complexitevisuel.setStyleSheet("background-color: red")
        elif len(password) < 10:
            strength = "Moyen"
            self.evaluationInterface.complexitevisuel.setStyleSheet("background-color: orange")
        else:
            strength = "Fort"
            self.evaluationInterface.complexitevisuel.setStyleSheet("background-color: green")

        self.evaluationInterface.complexitepassword.setText(f"Complexité du mot de passe : {strength}")

    # Fonction pour lancer Hydra
    def hydra_lancement(self):
        hydra_cible = self.evaluationInterface.hydracomboboxtarget.currentText()
        self.evaluationInterface.hydra_progressbar.setVisible(True)

        command = f"cd passwords-and-usernames && hydra -L top-usernames-shortlist.txt -P xato-net-10-million-passwords-10.txt {hydra_cible} ftp"
        self.worker = SSHWorker(command=command)
        self.worker.update_signal.connect(self.evaluationInterface.evaluationterminal.append)
        self.worker.finished_signal.connect(self.hydra_fin)  # Se connecter au slot pour la fin
        self.worker.start()

    # Fonction appelée à la fin de Hydra
    def hydra_fin(self):
        hydra_resultat = self.worker.output  # Accéder à l'attribut de sortie
        selected_profile = self.scanInterface.loadprofile.currentText()
        self.profile_manager.add_or_update_variable(selected_profile, "hydra_resultat", hydra_resultat)
        print("Sortie de la commande Hydra :", hydra_resultat)
        self.evaluationInterface.hydra_progressbar.setVisible(False)

    # Fonction pour les fylouts
    def infofly(self, icone, titre, contenu, cible,):
        Flyout.create(
                icon=icone,
                title=titre,
                content=contenu,
                target=cible,
                parent=self,
                isClosable=True,
                aniType=FlyoutAnimationType.PULL_UP
                )

    # Fonction pour gérer l'événement de fermeture
    def closeEvent(self, event):
        # Gérer l'événement de fermeture
        reply = QMessageBox.question(self, 'Message',
            "Êtes-vous sûr de vouloir fermer la PenToolBox ?", QMessageBox.Yes |
            QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            event.accept()
            self.qemu_manager.terminate_qemu()
            if self.worker and self.worker.isRunning():
                self.worker.finished.connect(lambda: self.worker.deleteLater())  # Attendre que le worker ait fini avant de supprimer
                self.worker.stop()  # Arrêter le worker
            else:
                QApplication.quit()
        else:
            event.ignore()

# Point d'entrée du programme
if __name__ == '__main__':
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)

    app = QApplication(sys.argv)
    w = main()
    w.show()
    sys.exit(app.exec_())
