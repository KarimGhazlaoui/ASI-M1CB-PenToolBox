import customtkinter
from PIL import Image

class leftsidebar:
    def __init__(self, parent):
        # create left_sidebar frame with widgets
        self.parent = parent
        self.left_sidebar_frame = customtkinter.CTkFrame(parent, width=140, corner_radius=0)
        self.left_sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.left_sidebar_frame.grid_rowconfigure(7, weight=1)

        htblogo = customtkinter.CTkImage(light_image=Image.open("img/logo/logo_large_wm.png"),
                                         dark_image=Image.open("img/logo/logo_large_bm.png"),
                                         size=(100, 123))

        self.logo_label = customtkinter.CTkLabel(self.left_sidebar_frame, text="", image=htblogo, corner_radius=0)
        self.logo_label.grid(row=0, column=0, padx=20, pady=10)

        self.left_sidebar_button_1 = customtkinter.CTkButton(self.left_sidebar_frame, command=self.left_sidebar_button_accueil, text="Accueil")
        self.left_sidebar_button_1.grid(row=1, column=0, padx=20, pady=10)
        self.left_sidebar_button_2 = customtkinter.CTkButton(self.left_sidebar_frame, command=self.left_sidebar_button_reconnaissance, text="Reconnaissance")
        self.left_sidebar_button_2.grid(row=2, column=0, padx=20, pady=10)
        self.left_sidebar_button_3 = customtkinter.CTkButton(self.left_sidebar_frame, command=self.left_sidebar_button_event, text="Scanning")
        self.left_sidebar_button_3.grid(row=3, column=0, padx=20, pady=10)
        self.left_sidebar_button_4 = customtkinter.CTkButton(self.left_sidebar_frame, command=self.left_sidebar_button_event, text="Exploitation")
        self.left_sidebar_button_4.grid(row=4, column=0, padx=20, pady=10)
        self.left_sidebar_button_5 = customtkinter.CTkButton(self.left_sidebar_frame, command=self.left_sidebar_button_event, text="Post-Exploitation")
        self.left_sidebar_button_5.grid(row=5, column=0, padx=20, pady=10)
        self.left_sidebar_button_6 = customtkinter.CTkButton(self.left_sidebar_frame, command=self.left_sidebar_button_event, text="Reporting")
        self.left_sidebar_button_6.grid(row=6, column=0, padx=20, pady=10)
        self.appearance_mode_label = customtkinter.CTkLabel(self.left_sidebar_frame, text="Mode d'affichage :", anchor="w")
        self.appearance_mode_label.grid(row=8, column=0, padx=20, pady=(10, 0))
        self.appearance_mode_optionemenu = customtkinter.CTkOptionMenu(self.left_sidebar_frame, values=["Light", "Dark", "System"],
                                                                       command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=9, column=0, padx=20, pady=(10, 10))
        self.scaling_label = customtkinter.CTkLabel(self.left_sidebar_frame, text="Taille d'affichage :", anchor="w")
        self.scaling_label.grid(row=10, column=0, padx=20, pady=(10, 0))
        self.scaling_optionemenu = customtkinter.CTkOptionMenu(self.left_sidebar_frame, values=["80%", "90%", "100%", "110%", "120%"],
                                                               command=self.change_scaling_event)
        self.scaling_optionemenu.grid(row=11, column=0, padx=20, pady=(10, 20))
        self.scaling_optionemenu.set("100%")
        self.appearance_mode_optionemenu.set("Dark")


    def left_sidebar_button_event(self):
        print("left_sidebar_button click")


    # test par rapport au grid via le bouton
    def left_sidebar_button_accueil(self):
        self.textbox = customtkinter.CTkTextbox(self.parent, width=250, height=150, state="normal")
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

    def left_sidebar_button_reconnaissance(self):
        self.textbox2 = customtkinter.CTkTextbox(self.parent, width=250, height=150, state="normal")
        self.textbox2.grid(row=0, column=1, padx=(20, 0), pady=(20, 0), sticky="nsew")
        self.textbox2.insert("0.0", "Guide d'utilisation\n\n" + "Test réussi si cela apparait.\n\n")
        self.textbox2.configure(state="disabled")

    def change_appearance_mode_event(self, new_appearance_mode: str):
        customtkinter.set_appearance_mode(new_appearance_mode)

    def change_scaling_event(self, new_scaling: str):
        new_scaling_float = int(new_scaling.replace("%", "")) / 100
        customtkinter.set_widget_scaling(new_scaling_float)
