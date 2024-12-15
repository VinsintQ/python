import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes

HOST = socket.gethostname()
PORT = 9999
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
public_pem = client.recv(1024)
server_public_key = load_pem_public_key(public_pem)
print("Server's Public Key:")
print(public_pem.decode())
try:
    while True:
        message = input("You: ")
        if message == "stop chat":
            encrypted_msg = server_public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            client.send(encrypted_msg)
            print("[+] Chat ended.")
            break
        encrypted_msg = server_public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        print(f"Sent (encrypted): {encrypted_msg.hex()}")
        client.send(encrypted_msg)
        response = client.recv(1024).decode()
        print(f"Server: {response}")
finally:
    client.close()
