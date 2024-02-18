from tkinter import *
from PIL import Image, ImageTk

root = Tk()

original_image = Image.open("img/splash/splash_transparency.png")
transparency_color = (0, 0, 0)  # Red color RGB values
image_rgba = original_image.convert("RGBA")
transparent_image = Image.new("RGBA", image_rgba.size, (255, 255, 255, 0))

for x in range(image_rgba.width):
    for y in range(image_rgba.height):
        r, g, b, a = image_rgba.getpixel((x, y))
        
        if (r, g, b) == transparency_color:
            a = 0
        
        transparent_image.putpixel((x, y), (r, g, b, a))

tk_image = ImageTk.PhotoImage(transparent_image)
image_width, image_height = transparent_image.size

height = image_height
width = image_width

x = (root.winfo_screenwidth() // 2) - (width // 2)
y = (root.winfo_screenheight() // 2) - (height // 2)
root.geometry(f"{width}x{height}+{x}+{y}")
root.overrideredirect(1)
canvas = Canvas(root, bg='white', bd=0, highlightthickness=0, width=width, height=height)
canvas.pack()
root.lift()
root.wm_attributes("-disabled", True)
root.wm_attributes("-transparentcolor", "white")
canvas.create_image(0, 0, anchor=NW, image=tk_image)

root.mainloop()
