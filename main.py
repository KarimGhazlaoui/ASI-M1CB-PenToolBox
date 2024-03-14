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

    def open_input_dialog_event(self):
        dialog = customtkinter.CTkInputDialog(text="Type in a number:", title="CTkInputDialog")
        print("CTkInputDialog:", dialog.get_input())


if __name__ == "__main__":
    app = App()
    app.mainloop()