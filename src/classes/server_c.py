import base64
import json
import socket
import ssl

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


class SecureServer:
    def __init__(
        self,
        host="0.0.0.0",
        port=12345,
        certfile="certs/server.crt",
        keyfile="certs/server.key",
        private_key="certs/server_private.pem",
    ):
        self.host = host
        self.port = port
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)

        # Load server's RSA private key
        with open(private_key, "rb") as f:
            self.server_private_key = RSA.import_key(f.read())

    def base64_decode(self, data):
        return base64.b64decode(data)

    def decrypt_aes_key(self, encrypted_key):
        """Decrypt AES key using server's private RSA key"""
        try:
            cipher_rsa = PKCS1_OAEP.new(self.server_private_key)
            return cipher_rsa.decrypt(self.base64_decode(encrypted_key))
        except ValueError:
            print("[ERROR] AES Key decryption failed!")
            return None

    def decrypt_message(self, aes_key, payload):
        """Decrypt a message using AES-GCM"""
        try:
            payload = json.loads(payload)
            cipher_aes = AES.new(
                aes_key, AES.MODE_GCM, nonce=self.base64_decode(payload["nonce"])
            )
            return cipher_aes.decrypt_and_verify(
                self.base64_decode(payload["ciphertext"]),
                self.base64_decode(payload["tag"]),
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
                "nonce": base64.b64encode(cipher_aes.nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "tag": base64.b64encode(tag).decode(),
            }
        )

    def start(self):
        """Start the secure server"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print("✅ Secure server is listening...")

            with self.context.wrap_socket(
                server_socket, server_side=True
            ) as secure_server:
                while True:
                    client_socket, addr = secure_server.accept()
                    print(f"🔒 Secure connection from {addr}")

                    try:
                        with client_socket:
                            # Receive encrypted AES key
                            encrypted_aes_key = client_socket.recv(1024).decode()
                            aes_key = self.decrypt_aes_key(encrypted_aes_key)
                            if not aes_key:
                                return

                            print("🔑 [SERVER] AES Key Decrypted.")

                            # Receive and decrypt message
                            payload = client_socket.recv(4096).decode()
                            decrypted_message = self.decrypt_message(aes_key, payload)
                            if decrypted_message:
                                print(
                                    f"📩 Received Secure Message: {decrypted_message}"
                                )

                                # Encrypt and send response
                                response_payload = self.encrypt_message(
                                    aes_key, "Hello from the E2EE server!"
                                )
                                client_socket.send(response_payload.encode())

                    except ConnectionResetError:
                        print("⚠️ [ERROR] Connection lost.")


# Run the server
if __name__ == "__main__":
    server = SecureServer()
    server.start()
