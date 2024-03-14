import tkinter as tk
from tkinter import *
import customtkinter
from PIL import Image, ImageTk

from main.splash.splash import SplashScreen
from main.sidebar.left_sidebar import leftsidebar
from scanning.scanning import NmapScannerApp

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.withdraw()

        # Create a splash screen
        self.splash = SplashScreen(self)  # Provide width and height parameters
        self.splash.after(5000, self.show_main_window)  # Schedule the splash screen to be destroyed after 5 seconds
        

    def show_main_window(self):

        customtkinter.set_appearance_mode("Dark")
        customtkinter.set_default_color_theme("blue")

        self.deiconify()

        # Destroy the splash screen and show the main window
        self.splash.destroy()
        self.title("PenToolBox by KGB")
        w = self.winfo_screenwidth() // 2 - 1280 // 2
        h = self.winfo_screenheight() // 2 - 720 // 2
        self.geometry('%dx%d+%d+%d' % (1280, 720, w, h))
        self.minsize(1280, 720)
        #self.maxsize(1860, 940)
        self.resizable(True, True)
        self.iconbitmap("img/logo/logo.ico")

        # configure grid layout (4x4)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3), weight=0)
        self.grid_rowconfigure((0, 1, 2), weight=1)
        
        # Appel de la sidebar gauche
        leftsidebar(self)
        NmapScannerApp(self)

        # create tabview
        NmapScannerApp(self)

        '''

        self.optionmenu_1 = customtkinter.CTkOptionMenu(self.tabview.tab("CTkTabview"), dynamic_resizing=False,
                                                        values=["Value 1", "Value 2", "Value Long Long Long"])
        self.optionmenu_1.grid(row=0, column=0, padx=20, pady=(20, 10))
        self.combobox_1 = customtkinter.CTkComboBox(self.tabview.tab("CTkTabview"),
                                                    values=["Value 1", "Value 2", "Value Long....."])
        self.combobox_1.grid(row=1, column=0, padx=20, pady=(10, 10))
        self.string_input_button = customtkinter.CTkButton(self.tabview.tab("CTkTabview"), text="Open CTkInputDialog",
                                                           command=self.open_input_dialog_event)
        self.string_input_button.grid(row=2, column=0, padx=20, pady=(10, 10))
        self.label_tab_2 = customtkinter.CTkLabel(self.tabview.tab("Tab 2"), text="CTkLabel on Tab 2")
        self.label_tab_2.grid(row=0, column=0, padx=20, pady=20)
        '''

        # create main entry and button
        '''
        self.entry = customtkinter.CTkEntry(self, placeholder_text="CTkEntry")
        self.entry.grid(row=3, column=1, columnspan=2, padx=(20, 0), pady=(20, 20), sticky="nsew")

        self.main_button_1 = customtkinter.CTkButton(master=self, fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"))
        self.main_button_1.grid(row=3, column=3, padx=(20, 20), pady=(20, 20), sticky="nsew")
        '''

        '''
        # create textbox
        self.textbox = customtkinter.CTkTextbox(self, width=250, height=150, state="normal")
        self.textbox.grid(row=0, column=1, padx=(20, 0), pady=(20, 0), sticky="nsew")
        self.textbox.insert("0.0", "Pen Tool Box\n\n" + "Conditions d'utilisation.\n\n" + 
                            "Cet outil de pentest est destiné à être utilisé uniquement à des fins légales et éthiques.\n\n" + 
                            "En utilisant cet outil, vous acceptez de vous conformer aux lois en vigueur dans votre pays et de respecter les principes éthiques de la sécurité informatique.\n\n" + 
                            "Vous ne devez en aucun cas utiliser cet outil pour effectuer des activités malveillantes, illégales ou non autorisées.\n\n" +
                            "Ces activités incluent l'accès non autorisé à des systèmes informatiques, la perturbation des services en ligne, le vol d'informations confidentielles ou toute autre action susceptible de causer un préjudice.\n\n" +
                            "L'utilisation de cet outil sur des systèmes informatiques sans l'autorisation expresse et écrite du propriétaire est strictement interdite.\n\n" + 
                            "Il est de votre responsabilité de vous assurer que vous avez le consentement approprié avant de tester la sécurité d'un système.\n\n" + 
                            "En aucun cas, les développeurs de cet outil ne peuvent être tenus responsables de toute utilisation abusive ou illégale de celui-ci.\n\n" + 
                            "Tout usage contraire à ces conditions constitue une violation des droits d'auteur et peut entraîner des poursuites judiciaires.\n\n" + 
                            "En utilisant cet outil, vous reconnaissez avoir lu, compris et accepté ces conditions d'utilisation. Si vous n'acceptez pas ces conditions, vous ne devez pas utiliser cet outil.")
        self.textbox.configure(state="disabled")
        '''    

        #self.seg_button_1.configure(values=["Réseau", "EndPoint", "Vulnérabilité"])
        #self.seg_button_1.set("Value 2")

        # Barre de progression
        #self.progressbar_1 = customtkinter.CTkProgressBar(self, progress_color="green")
        #self.progressbar_1.grid(row=3, column=1, padx=(20, 10), pady=(10, 10), sticky="ew")
        #self.progressbar_1.configure(mode="determinate")
        #self.progressbar_1.set(0.2)

    def open_input_dialog_event(self):
        dialog = customtkinter.CTkInputDialog(text="Type in a number:", title="CTkInputDialog")
        print("CTkInputDialog:", dialog.get_input())


if __name__ == "__main__":
    app = App()
    app.mainloop()