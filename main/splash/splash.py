import tkinter as tk
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
        width, height = self.transparent_image.size
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'+{x}+{y}')
        
        self.overrideredirect(1)
        self.canvas = tk.Canvas(self, bg='white', bd=0, highlightthickness=0, width=width, height=height)
        self.canvas.pack()
        self.lift()
        self.wm_attributes("-disabled", True)
        self.wm_attributes("-transparentcolor", "white")
        self.canvas.create_image(0, 0, anchor=tk.NW, image=self.tk_image)