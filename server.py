# server.py
import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()


public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
print("Server's Public Key:")
print(public_pem.decode())


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
            print(f"Received (encrypted): {encrypted_msg.hex()}")
            print(f"Received (decrypted): {decrypted_msg}")

            if decrypted_msg == "[stop chat]":
                print("[-] Chat stopped by client.")
                break

            response = "Message received"
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
