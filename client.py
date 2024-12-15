import socket
import rsa
from Crypto.Cipher import AES
import base64


def encrypt_message(message, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return cipher.nonce + ciphertext


def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 12345))

    server_public_key_data = client_socket.recv(4096)
    server_public_key = rsa.PublicKey.load_pkcs1(server_public_key_data)

    aes_key = base64.urlsafe_b64encode(AES.get_random_bytes(16))
    print(f"Client AES Key: {aes_key}")  # Print AES Key
    encrypted_aes_key = rsa.encrypt(aes_key, server_public_key)
    client_socket.send(encrypted_aes_key)

    # Wait for the server to recieve of the AES key
    response = client_socket.recv(4096).decode()
    if response == "AES Key received.":
        print("Keys exchanged successfully. You can now send messages.")
    else:
        print("Error: Server did not acknowledge the AES key.")

    while True:
        message = input("Enter message (type 'END' to quit): ")
        encrypted_message = encrypt_message(message, aes_key)
        client_socket.send(encrypted_message)
        response = client_socket.recv(4096).decode()
        print(f"Server response: {response}")
        if message == "END":
            break

    client_socket.close()


if __name__ == "__main__":
    start_client()
