import tkinter as tk
import customtkinter
from PIL import Image, ImageTk

class SplashScreen(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.original_image = Image.open("img/splash/splash_transparency.png")
        self.transparency_color = (0, 0, 0)  # Red color RGB values
        self.image_rgba = self.original_image.convert("RGBA")
        self.transparent_image = Image.new("RGBA", self.image_rgba.size, (255, 255, 255, 0))

        for x in range(self.image_rgba.width):
            for y in range(self.image_rgba.height):
                r, g, b, a = self.image_rgba.getpixel((x, y))
                
                if (r, g, b) == self.transparency_color:
                    a = 0
                
                self.transparent_image.putpixel((x, y), (r, g, b, a))

        self.tk_image = ImageTk.PhotoImage(self.transparent_image)
        image_width, image_height = self.transparent_image.size

        height = image_height
        width = image_width

        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.overrideredirect(1)
        self.canvas = tk.Canvas(self, bg='white', bd=0, highlightthickness=0, width=width, height=height)
        self.canvas.pack()
        self.lift()
        self.wm_attributes("-disabled", True)
        self.wm_attributes("-transparentcolor", "white")
        self.canvas.create_image(0, 0, anchor=tk.NW, image=self.tk_image)



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
        w = self.winfo_screenwidth() // 2 - 1860 // 2
        h = self.winfo_screenheight() // 2 - 940 // 2
        self.geometry('%dx%d+%d+%d' % (1860, 940, w, h))
        self.minsize(1860, 940)
        self.maxsize(1860, 940)
        self.resizable(False, False)
        self.iconbitmap("img/logo/logo.ico")

        # configure grid layout (4x4)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3), weight=0)
        self.grid_rowconfigure((0, 1, 2), weight=1)

        # create sidebar frame with widgets
        self.sidebar_frame = customtkinter.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(7, weight=1)

        htblogo = customtkinter.CTkImage(light_image=Image.open("img/logo/logo_large_wm.png"),
                                         dark_image=Image.open("img/logo/logo_large_bm.png"),
                                         size=(100, 123))

        self.logo_label = customtkinter.CTkLabel(self.sidebar_frame, text="", image=htblogo, corner_radius=0)
        self.logo_label.grid(row=0, column=0, padx=20, pady=10)

        self.sidebar_button_1 = customtkinter.CTkButton(self.sidebar_frame, command=self.sidebar_button_event, text="Accueil")
        self.sidebar_button_1.grid(row=1, column=0, padx=20, pady=10)
        self.sidebar_button_2 = customtkinter.CTkButton(self.sidebar_frame, command=self.sidebar_button_event, text="Reconnaissance")
        self.sidebar_button_2.grid(row=2, column=0, padx=20, pady=10)
        self.sidebar_button_3 = customtkinter.CTkButton(self.sidebar_frame, command=self.sidebar_button_event, text="Scanning")
        self.sidebar_button_3.grid(row=3, column=0, padx=20, pady=10)
        self.sidebar_button_4 = customtkinter.CTkButton(self.sidebar_frame, command=self.sidebar_button_event, text="Exploitation")
        self.sidebar_button_4.grid(row=4, column=0, padx=20, pady=10)
        self.sidebar_button_5 = customtkinter.CTkButton(self.sidebar_frame, command=self.sidebar_button_event, text="Post-Exploitation")
        self.sidebar_button_5.grid(row=5, column=0, padx=20, pady=10)
        self.sidebar_button_6 = customtkinter.CTkButton(self.sidebar_frame, command=self.sidebar_button_event, text="Reporting")
        self.sidebar_button_6.grid(row=6, column=0, padx=20, pady=10)
        self.appearance_mode_label = customtkinter.CTkLabel(self.sidebar_frame, text="Mode d'affichage :", anchor="w")
        self.appearance_mode_label.grid(row=8, column=0, padx=20, pady=(10, 0))
        self.appearance_mode_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame, values=["Light", "Dark", "System"],
                                                                       command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=9, column=0, padx=20, pady=(10, 10))
        self.scaling_label = customtkinter.CTkLabel(self.sidebar_frame, text="Taille d'affichage :", anchor="w")
        self.scaling_label.grid(row=10, column=0, padx=20, pady=(10, 0))
        self.scaling_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame, values=["80%", "90%", "100%", "110%", "120%"],
                                                               command=self.change_scaling_event)
        self.scaling_optionemenu.grid(row=11, column=0, padx=20, pady=(10, 20))
        self.scaling_optionemenu.set("100%")
        self.appearance_mode_optionemenu.set("Dark")

        # create main entry and button
        '''
        self.entry = customtkinter.CTkEntry(self, placeholder_text="CTkEntry")
        self.entry.grid(row=3, column=1, columnspan=2, padx=(20, 0), pady=(20, 20), sticky="nsew")

        self.main_button_1 = customtkinter.CTkButton(master=self, fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"))
        self.main_button_1.grid(row=3, column=3, padx=(20, 20), pady=(20, 20), sticky="nsew")
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
        

        #self.seg_button_1.configure(values=["Réseau", "EndPoint", "Vulnérabilité"])
        #self.seg_button_1.set("Value 2")

        # Barre de progression
        self.progressbar_1 = customtkinter.CTkProgressBar(self)
        self.progressbar_1.grid(row=3, column=1, padx=(20, 10), pady=(10, 10), sticky="ew")
        self.progressbar_1.configure(mode="determinate")
        self.progressbar_1.set(0.2)

    def open_input_dialog_event(self):
        dialog = customtkinter.CTkInputDialog(text="Type in a number:", title="CTkInputDialog")
        print("CTkInputDialog:", dialog.get_input())

    def change_appearance_mode_event(self, new_appearance_mode: str):
        customtkinter.set_appearance_mode(new_appearance_mode)

    def change_scaling_event(self, new_scaling: str):
        new_scaling_float = int(new_scaling.replace("%", "")) / 100
        customtkinter.set_widget_scaling(new_scaling_float)

    def sidebar_button_event(self):
        print("sidebar_button click")


if __name__ == "__main__":
    app = App()
    app.mainloop()