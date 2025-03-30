import json
import socket
import sqlite3
import ssl
import threading
from hashlib import sha256

from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse


class SecureServer:
    def __init__(self, host, port, certfile, keyfile, private_key, db_path):
        self.host = host
        self.port = port
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)

        # Load RSA private key
        with open(private_key, "rb") as f:
            self.server_private_key = RSA.import_key(f.read())

        # SQLite database path
        self.db_path = db_path

        # Connect to SQLite database (Main thread only)
        self.con = sqlite3.connect(self.db_path)
        self.cur = self.con.cursor()

        # Initialize DB tables
        self.init_db()

    def init_db(self):
        """Initialize the database and create tables if they don't exist."""
        # Create a table for storing users' credentials (username, password hash)
        self.cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
            """
        )
        # Create a table to log connection events
        self.cur.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Initialize default user and password only if it does not exist
        self.cur.execute("SELECT * FROM users WHERE username = ?", ("admin",))
        if not self.cur.fetchone():
            # Default username and password
            username = "admin"
            password = "admin"
            # Hash the password
            password_hash = sha256(password.encode()).hexdigest()
            self.cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            self.cur.execute(
                "INSERT INTO logs (message) VALUES (?)", ("Initial setup",)
            )
            self.con.commit()

    def authenticate_user(self, username, password):
        """Authenticate the user by checking the username and password hash from the SQLite database."""
        # Open a new connection to the database for each thread
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        cur.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),
        )
        user = cur.fetchone()
        conn.close()

        if user:
            stored_hash = user[0]
            # Hash the input password and compare with stored hash
            input_password_hash = sha256(password.encode()).hexdigest()
            return stored_hash == input_password_hash
        return False

    def log_event(self, message):
        """Log events (e.g., successful login, blind sign request) to the SQLite database."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("INSERT INTO logs (message) VALUES (?)", (message,))
        conn.commit()
        conn.close()

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
                # First, authenticate the user
                credentials = client_socket.recv(4096).decode("utf-8")
                credentials_data = json.loads(credentials)
                username = credentials_data.get("username")
                password = credentials_data.get("password")

                # Authenticate user
                if self.authenticate_user(username, password):
                    client_socket.send("Authentication successful".encode("utf-8"))
                    print(f"✅ [SERVER] User {username} authenticated successfully.")
                    self.log_event(f"User {username} authenticated.")
                else:
                    client_socket.send("Authentication failed".encode("utf-8"))
                    print(f"⚠️ [SERVER] Authentication failed for {username}.")
                    self.log_event(f"Authentication failed for {username}.")
                    return  # Close connection after authentication failure

                # Proceed with blind signing
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
                            self.log_event(f"Sent blind signature to {addr}")
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
                finally:
                    # Close the main connection when server shuts down
                    self.con.close()
