import requests
import hashlib
import os
import json
import difflib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SENDER_EMAIL = "mjdoradoacens@gmail.com"
RECEIVER_EMAIL = "mjdoradoacens@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD')

urls_to_monitor = [
    "https://security.netapp.com/advisory/ntap-20260610-0003",
    "https://security.netapp.com/advisory/ntap-20260710-0020",
    "https://security.netapp.com/advisory/ntap-20260501-0001",
    "https://security.netapp.com/advisory/ntap-20260513-0001",
    "https://security.netapp.com/advisory/NTAP-20261021-0021"
]

HASH_FILE = "url_hashes.json"
CONTENT_DIR = "saved_pages"
os.makedirs(CONTENT_DIR, exist_ok=True)

def send_email_alert(subject, body_text):
    if not EMAIL_PASSWORD:
        print("[Error] EMAIL_PASSWORD no configurado en entorno de GitHub.")
        return
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        msg['Subject'] = subject
        msg.attach(MIMEText(body_text, 'plain', 'utf-8'))
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, EMAIL_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        print("[Correo] Alerta enviada con éxito.")
    except Exception as e:
        print(f"[Error Correo] {e}")

def load_previous_hashes():
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_hashes(hashes):
    with open(HASH_FILE, 'w') as f:
        json.dump(hashes, f, indent=4)

def get_page_filename(url):
    safe_name = url.replace("https://", "").replace("http://", "").replace("/", "_")
    return os.path.join(CONTENT_DIR, f"{safe_name}.txt")

def check_for_changes_with_email():
    previous_hashes = load_previous_hashes()
    current_hashes = {}
    changes_detected = False
    email_alerts = []

    for url in urls_to_monitor:
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=15, verify=False)
            response.raise_for_status()

            current_text = response.text
            content_hash = hashlib.md5(current_text.encode('utf-8')).hexdigest()
            current_hashes[url] = content_hash

            page_file_path = get_page_filename(url)

            if url in previous_hashes:
                if previous_hashes[url] != content_hash:
                    alert_message = f"¡El aviso ha cambiado!: {url}\n"
                    changes_detected = True

                    if os.path.exists(page_file_path):
                        with open(page_file_path, 'r', encoding='utf-8') as f:
                            old_text_lines = f.readlines()
                        current_text_lines = current_text.splitlines(keepends=True)
                        diff = difflib.unified_diff(
                            old_text_lines,
                            current_text_lines,
                            fromfile='Contenido Anterior',
                            tofile='Contenido Nuevo',
                            n=2
                        )
                        diff_text = "".join(list(diff)[:30])
                        alert_message += f"Diferencias detectadas:\n{diff_text}\n"
                    else:
                        alert_message += "No se encontró copia previa para comparar.\n"
                    email_alerts.append(alert_message)

            with open(page_file_path, 'w', encoding='utf-8') as f:
                f.write(current_text)
        except Exception as e:
            print(f"[Error] {url}: {e}")
            if url in previous_hashes:
                current_hashes[url] = previous_hashes[url]

    save_hashes(current_hashes)

    if changes_detected and email_alerts:
        subject = "[NetApp Monitor] ¡Cambios detectados!"
        body = "Se detectaron cambios en las siguientes páginas:\n\n" + "\n---\n".join(email_alerts)
        send_email_alert(subject, body)
    else:
        print("Sin cambios detectados.")

if __name__ == "__main__":
    check_for_changes_with_email()
