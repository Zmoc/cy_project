import json
import socket
import ssl
from abc import ABC, abstractmethod

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


class SecureClient:
    def __init__(self, server_host, server_port, certfile, public_key):
        self.server_host = server_host
        self.server_port = server_port
        self.context = ssl.create_default_context()
        self.context.load_verify_locations(certfile)

        # Load server's public RSA key
        with open(public_key, "rb") as f:
            self.server_public_key = RSA.import_key(f.read())

    def encrypt_aes_key(self, aes_key):
        """Encrypt AES key using RSA"""
        cipher_rsa = PKCS1_OAEP.new(self.server_public_key)
        return cipher_rsa.encrypt(aes_key)

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
            return None  # Handle decryption failure

    @abstractmethod
    def message(self):
        pass

    def send_aes_key(self, secure_socket):
        aes_key = get_random_bytes(32)  # 256-bit AES key
        encrypted_aes_key = self.encrypt_aes_key(aes_key)
        secure_socket.send(encrypted_aes_key)
        print("🔑 [CLIENT] AES Key Sent Securely.")
        return aes_key

    def rcvd_decrypt(self, secure_socket, aes_key):
        response_payload = secure_socket.recv(4096).decode()
        decrypted_response = self.decrypt_message(aes_key, response_payload)
        return decrypted_response

    def send_encrypt(self, secure_socket, aes_key):
        message = self.message()
        encrypted_payload = self.encrypt_message(aes_key, message)
        secure_socket.send(encrypted_payload.encode())
        return message

    def connect(self):
        """Connect to the secure server"""
        with socket.create_connection(
            (self.server_host, self.server_port)
        ) as client_socket:
            with self.context.wrap_socket(
                client_socket, server_hostname=self.server_host
            ) as secure_socket:
                print("🔒 [CLIENT] Secure connection established.")

                try:
                    # Step 1: Generate and send AES key
                    aes_key = self.send_aes_key(secure_socket)

                    while True:
                        # Step 2: Get user input and send encrypted message
                        message = self.send_encrypt(secure_socket, aes_key)

                        if message.lower() == "exit":
                            print("🔴 [CLIENT] Disconnecting...")
                            break

                        # Step 3: Receive and decrypt response
                        decrypted_response = self.rcvd_decrypt(secure_socket, aes_key)

                        if decrypted_response:
                            print(f"📩 [CLIENT] Server Response: {decrypted_response}")

                except ConnectionResetError:
                    print("⚠️ [ERROR] Connection lost.")
