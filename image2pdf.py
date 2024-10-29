import os
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from fpdf import FPDF
from rich.console import Console

console = Console()

def convert_images_to_pdf(image_paths, output_path):
    """Convert multiple images into a single PDF."""
    pdf = FPDF()
    console.status("Converting images to PDF...")

    for image_path in image_paths:
        try:
            image = Image.open(image_path)
            console.log(f"Opened image: {image_path}")

            # Add the image to the PDF
            pdf.add_page()
            pdf.image(image_path, x=0, y=0, w=210, h=297)  # Fit image to A4 page size
            console.log(f"Added image to PDF: {image_path}")
        except Exception as e:
            console.print(f"[bold red]Error processing image: {image_path} - {str(e)}[/bold red]")

    pdf.output(output_path, "F")
    console.print(f"[bold green]PDF saved to: {output_path}[/bold green]")

def select_images():
    root = tk.Tk()
    root.withdraw()
    image_paths = filedialog.askopenfilenames(
        title="Select images to convert",
        filetypes=[
            ("Image files", "*.jpg;*.jpeg;*.png;*.bmp;*.gif;*.tiff"),
            ("All files", "*.*")  
        ]
    )
    return list(image_paths)  # Return a list of file paths

def select_output_path():
    root = tk.Tk()
    root.withdraw()
    output_path = filedialog.asksaveasfilename(
        title="Save PDF as",
        defaultextension=".pdf",
        filetypes=[("PDF files", "*.pdf")]
    )
    return output_path

class ImagePreviewApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image to PDF Converter")
        self.image_paths = []
        self.image_labels = []  # Store references to image labels for garbage collection

        # Create frames
        self.preview_frame = tk.Frame(self.root, padx=10, pady=10)
        self.preview_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.control_frame = tk.Frame(self.root, padx=10, pady=10)
        self.control_frame.pack(side=tk.RIGHT, fill=tk.Y)

        # Create a canvas for image preview
        self.canvas = tk.Canvas(self.preview_frame)
        self.canvas.pack(fill=tk.BOTH, expand=True)

        # Create a scrollbar for the canvas
        self.scrollbar = tk.Scrollbar(self.preview_frame, command=self.canvas.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Create a frame for image labels
        self.inner_frame = tk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.inner_frame, anchor='nw')

        # Create control buttons
        self.select_images_button = tk.Button(self.control_frame, text="Select Images", command=self.select_images)
        self.select_images_button.pack(pady=5)

        self.convert_button = tk.Button(self.control_frame, text="Convert to PDF", command=self.convert_to_pdf)
        self.convert_button.pack(pady=5)

        self.output_path_label = tk.Label(self.control_frame, text="Output Path:")
        self.output_path_label.pack(pady=5)
        self.output_path_entry = tk.Entry(self.control_frame, width=40)
        self.output_path_entry.pack(pady=5)
        self.browse_button = tk.Button(self.control_frame, text="Browse", command=self.browse_output_path)
        self.browse_button.pack(pady=5)

    def select_images(self):
        self.image_paths = select_images()
        if self.image_paths:  
            self.preview_images()
        else:
            console.print("[bold red]No images selected.[/bold red]")

    def preview_images(self):
        # Clear previous previews
        for widget in self.inner_frame.winfo_children():
            widget.destroy()
        self.image_labels.clear()

        for image_path in self.image_paths:
            try:
                # Open and load the image
                image = Image.open(image_path)
                image.thumbnail((200, 200))  
                photo = ImageTk.PhotoImage(image)

                # Create a new label for the image
                label = tk.Label(self.inner_frame, image=photo)
                label.image = photo  
                label.pack(side=tk.TOP, pady=5)

                # Store the label reference to prevent it from being garbage collected
                self.image_labels.append(label)

                # Print image dimensions
                console.log(f"Image dimensions: {image.size}")

            except Exception as e:
                console.print(f"[bold red]Error previewing image: {image_path} - {str(e)}[/bold red]")

        # Update the scroll region of the canvas
        self.inner_frame.update_idletasks()
        self.canvas.config(scrollregion=self.canvas.bbox("all"))

    def browse_output_path(self):
        output_path = select_output_path()
        if output_path:  # Check if a path is actually selected
            self.output_path_entry.delete(0, tk.END)
            self.output_path_entry.insert(0, output_path)

    def convert_to_pdf(self):
        output_path = self.output_path_entry.get()
        if not output_path:
            messagebox.showerror("Error", "Please enter an output path.")
            console.print("[bold red]Please enter an output path.[/bold red]")
            return
        
        if os.path.isdir(output_path):
            messagebox.showerror("Error", "Output path is a directory. Please select a file path.")
            console.print("[bold red]Output path is a directory. Please select a file path.[/bold red]")
            return

        convert_images_to_pdf(self.image_paths, output_path)

def main():
    console.print("[bold magenta]Image to PDF Converter[/bold magenta]")
    console.print("-----------------------------------------")

    root = tk.Tk()
    app = ImagePreviewApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()

