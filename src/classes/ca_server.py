import json
import socket
import ssl
import threading

from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse


class SecureServer:
    def __init__(self, host, port, certfile, keyfile, private_key):
        self.host = host
        self.port = port
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)

        # Load RSA private key
        with open(private_key, "rb") as f:
            self.server_private_key = RSA.import_key(f.read())

    def blind_sign(self, blinded_message_hex):
        """Signs the blinded message received from the client."""
        try:
            blinded_message = int(blinded_message_hex, 16)
            d, n = self.server_private_key.d, self.server_private_key.n
            blinded_signature = pow(blinded_message, d, n)  # RSA blind signing
            return hex(blinded_signature)[2:]  # Convert to hex string
        except Exception as e:
            print(f"⚠️ [ERROR] Blind signing failed: {e}")
            return None

    def handle_client(self, client_socket, addr):
        """Handles client requests for blind signing."""
        try:
            with client_socket:
                while True:
                    request = client_socket.recv(4096).decode("utf-8")
                    if not request:
                        break

                    try:
                        request_data = json.loads(request)
                        if "blinded_message" in request_data:
                            blinded_signature = self.blind_sign(
                                request_data["blinded_message"]
                            )
                            response = (
                                json.dumps({"signature": blinded_signature})
                                if blinded_signature
                                else json.dumps({"error": "Signing failed"})
                            )
                            client_socket.send(response.encode("utf-8"))
                            print(f"✅ [SERVER] Sent blind signature to {addr}")
                    except json.JSONDecodeError:
                        print(f"⚠️ [ERROR] Invalid JSON from {addr}")

        except ConnectionResetError:
            print(f"⚠️ [ERROR] Connection lost from {addr}")
        finally:
            print(f"🔌 [SERVER] Closing connection with {addr}")

    def start(self):
        """Starts the secure server and listens for clients."""
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

                        threading.Thread(
                            target=self.handle_client,
                            args=(client_socket, addr),
                            daemon=True,
                        ).start()

                except KeyboardInterrupt:
                    print("\n🔴 [SERVER] Shutting down...")
