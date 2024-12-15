import socket
import threading
import rsa
from Crypto.Cipher import AES
import base64
import requests
import json

VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2/url/report"
API_KEY = "e3483f413198a1f057a2bf691c0cb0602996fe953e49b15a061815743e90c582"  # Replace with your VirusTotal API key


def generate_rsa_keys():
    public_key, private_key = rsa.newkeys(2048)
    return public_key, private_key


def decrypt_message(encrypted_message, private_key):
    return rsa.decrypt(encrypted_message, private_key).decode()


def check_url_safety(url):
    params = {"apikey": API_KEY, "resource": url}
    response = requests.get(VIRUSTOTAL_URL, params=params)
    result = response.json().get("positives", 0)
    return "Safe URL" if result == 0 else "Unsafe URL"


def handle_client(client_socket, private_key):
    aes_key = None
    while True:
        encrypted_message = client_socket.recv(4096)
        if not encrypted_message:
            break

        if aes_key is None:
            try:
                aes_key = decrypt_message(encrypted_message, private_key).encode()
                print(f"AES Key received: {aes_key}")  # Debug log
                client_socket.send(b"AES Key received.")
            except Exception as e:
                print(f"Error decrypting AES key: {e}")  # Debug log
                client_socket.send(b"Failed to set AES Key.")
            continue

        try:
            cipher = AES.new(aes_key, AES.MODE_EAX, nonce=encrypted_message[:16])
            decrypted_message = cipher.decrypt(encrypted_message[16:]).decode()
            print(f"Received: {decrypted_message}")

            if "http" in decrypted_message:
                url_status = check_url_safety(decrypted_message)
                client_socket.send(url_status.encode())
            else:
                client_socket.send(f"Echo: {decrypted_message}".encode())

            if decrypted_message == "END":
                break
        except Exception as e:
            print(f"Error processing the message: {e}")  # Debug log
            client_socket.send(b"Error processing the message.")
            continue

    client_socket.close()


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 12345))
    server_socket.listen(5)
    print("Server is running...")

    public_key, private_key = generate_rsa_keys()
    print(f"Server RSA Public Key: {public_key}")  # Print RSA Public Key

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        client_socket.send(public_key.save_pkcs1())
        threading.Thread(
            target=handle_client, args=(client_socket, private_key)
        ).start()


if __name__ == "__main__":
    start_server()
