import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os
import re
import requests
import urllib3

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_KEY = "e3483f413198a1f057a2bf691c0cb0602996fe953e49b15a061815743e90c582"
VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2/url/report"


def extract_url(text):
    url_pattern = re.compile(r"https?://\S+|www\.\S+")
    match = url_pattern.search(text)
    return match.group(0) if match else None


def check_url_safety(url):
    params = {"apikey": API_KEY, "resource": url}
    try:
        response = requests.get(VIRUSTOTAL_URL, params=params, verify=False)
        response.raise_for_status()
        result = response.json()

        if result.get("response_code") == 1:
            if result.get("positives", 0) > 0:
                return f"WARNING: The URL '{url}' is flagged as malicious."
            else:
                return f"The URL '{url}' is safe."
        else:
            return "Could not check the URL. It might be invalid or unavailable."
    except requests.exceptions.RequestException as e:
        return f"An error occurred while checking the URL: {e}"
    except ValueError:
        return "Error: The response from VirusTotal was not in a valid JSON format."


private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

HOST = socket.gethostname()
PORT = 9999


def handle_client(conn, addr):
    print(f"[+] Connected to {addr}")

    conn.send(public_pem)

    try:
        while True:
            encrypted_msg = conn.recv(1024)
            if not encrypted_msg:
                break

            decrypted_msg = private_key.decrypt(
                encrypted_msg,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            ).decode()
            print(f"Received: {decrypted_msg}")

            if decrypted_msg == "[stop chat]":
                print("[-] Chat stopped by client.")
                break

            url = extract_url(decrypted_msg)
            if url:
                response = check_url_safety(url)

            conn.send(response.encode("utf-8"))
    finally:
        conn.close()


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)
print(f"[+] Server running on {HOST}:{PORT}")


while True:
    client_socket, client_address = server.accept()
    threading.Thread(target=handle_client, args=(client_socket, client_address)).start()
