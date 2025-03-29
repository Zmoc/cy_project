import json
import socket
import ssl
import threading
from abc import ABC, abstractmethod

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


class SecureServer:
    def __init__(self, host, port, certfile, keyfile, private_key):
        self.host = host
        self.port = port
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)

        # Load RSA private key
        with open(private_key, "rb") as f:
            self.server_private_key = RSA.import_key(f.read())

        self.clients = []  # Track active client threads

    def decrypt_aes_key(self, encrypted_key):
        """Decrypt AES key using server's private RSA key"""
        try:
            cipher_rsa = PKCS1_OAEP.new(self.server_private_key)
            return cipher_rsa.decrypt(encrypted_key)
        except ValueError:
            print("[ERROR] AES Key decryption failed!")
            return None

    def decrypt_message(self, aes_key, payload):
        """Decrypt a message using AES-GCM"""
        try:
            payload = json.loads(payload)
            cipher_aes = AES.new(
                aes_key, AES.MODE_GCM, nonce=bytes.fromhex(payload["nonce"])
            )
            return cipher_aes.decrypt_and_verify(
                bytes.fromhex(payload["ciphertext"]),
                bytes.fromhex(payload["tag"]),
            ).decode()
        except (ValueError, KeyError, json.JSONDecodeError):
            print("[ERROR] Message decryption failed!")
            return None

    def encrypt_message(self, aes_key, message):
        """Encrypt a message using AES-GCM"""
        cipher_aes = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
        return json.dumps(
            {
                "nonce": cipher_aes.nonce.hex(),
                "ciphertext": ciphertext.hex(),
                "tag": tag.hex(),
            }
        )

    def send_encrypt(self, client_socket, aes_key, decrypted_message):
        response_payload = self.encrypt_message(
            aes_key, f"Server received: {decrypted_message}"
        )
        client_socket.send(response_payload.encode())

    def handle_client(self, client_socket, addr):
        """Handles communication with a single client"""
        try:
            with client_socket:
                # Receive encrypted AES key
                encrypted_aes_key = client_socket.recv(1024)
                aes_key = self.decrypt_aes_key(encrypted_aes_key)
                if not aes_key:
                    return

                print(f"🔑 [SERVER] AES Key Decrypted for {addr}")

                while True:
                    # Receive encrypted message
                    payload = client_socket.recv(4096).decode()
                    if not payload:
                        break  # Client disconnected

                    decrypted_message = self.decrypt_message(aes_key, payload)
                    if decrypted_message:
                        print(f"📩 [SERVER] Received from {addr}: {decrypted_message}")

                        # If client sends "exit", close connection
                        if decrypted_message.lower() == "exit":
                            print(f"🔴 [SERVER] {addr} disconnected.")
                            break

                        # Send encrypted response
                        self.send_encrypt(client_socket, aes_key, decrypted_message)

        except ConnectionResetError:
            print(f"⚠️ [ERROR] Connection lost from {addr}")

        finally:
            print(f"🔌 [SERVER] Closing connection with {addr}")

    def start(self):
        """Starts the secure server and listens for clients"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print(f"✅ Secure server is listening on {self.host}:{self.port}")

            with self.context.wrap_socket(
                server_socket, server_side=True
            ) as secure_server:
                try:
                    while True:
                        client_socket, addr = secure_server.accept()
                        print(f"🔒 Secure connection from {addr}")

                        # Start a new thread for each client
                        client_thread = threading.Thread(
                            target=self.handle_client, args=(client_socket, addr)
                        )
                        client_thread.daemon = True  # Allows the program to exit even if threads are running
                        client_thread.start()

                        # Keep track of threads
                        self.clients.append(client_thread)

                except KeyboardInterrupt:
                    print("\n🔴 [SERVER] Shutting down...")
                finally:
                    # Ensure all client threads are closed before exiting
                    for thread in self.clients:
                        thread.join()
