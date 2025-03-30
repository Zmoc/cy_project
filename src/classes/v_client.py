import json
import socket
import sqlite3
import ssl

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, inverse


class SecureClient:
    def __init__(self, server_host, server_port, certfile, public_key, db_path):
        self.server_host = server_host
        self.server_port = server_port
        self.context = ssl.create_default_context()
        self.context.load_verify_locations(certfile)
        self.db_path = db_path

        # Load server's public RSA key
        with open(public_key, "rb") as f:
            self.server_public_key = RSA.import_key(f.read())

        self.con = sqlite3.connect(self.db_path)
        self.cur = self.con.cursor()
        self.init_db()

    def init_db(self):
        """Creates the database tables if they do not exist."""
        self.cur.execute(
            """CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL,
                signature TEXT,
                verified INTEGER
            )"""
        )
        self.con.commit()

    def save_message(self, message, signature, verified):
        """Stores messages and their corresponding signatures in the database."""
        self.cur.execute(
            "INSERT INTO messages (message, signature, verified) VALUES (?, ?, ?)",
            (message, signature, verified),
        )
        self.con.commit()

    def blind_message(self, message):
        """Blinds a message before sending it for signing."""
        try:
            n = self.server_public_key.n
            e = self.server_public_key.e
            r = getPrime(256)  # Random blinding factor
            r_inv = inverse(r, n)  # Compute modular inverse

            message_hash = SHA256.new(message.encode()).digest()
            m = int.from_bytes(message_hash, "big")
            blinded_message = (m * pow(r, e, n)) % n  # Blind the message

            return hex(blinded_message)[2:], r_inv  # Convert to hex
        except Exception as e:
            print(f"⚠️ [ERROR] Blinding failed: {e}")
            return None, None

    def unblind_signature(self, blinded_signature_hex, r_inv):
        """Unblinds the received signature."""
        try:
            n = self.server_public_key.n
            blinded_signature = int(blinded_signature_hex, 16)
            signature = (blinded_signature * r_inv) % n  # Unblind signature
            return hex(signature)[2:]
        except Exception as e:
            print(f"⚠️ [ERROR] Unblinding failed: {e}")
            return None

    def verify_signature(self, message, signature_hex):
        """Verifies the RSA signature."""
        try:
            signature = int(signature_hex, 16)
            n = self.server_public_key.n
            e = self.server_public_key.e

            message_hash = SHA256.new(message.encode()).digest()
            m = int.from_bytes(message_hash, "big")

            verified_message = pow(signature, e, n)  # Verify RSA signature
            return verified_message == m
        except Exception as e:
            print(f"⚠️ [ERROR] Signature verification failed: {e}")
            return False

    def connect(self):
        """Connect to the secure server and perform operations."""
        client_socket = socket.create_connection((self.server_host, self.server_port))
        secure_socket = self.context.wrap_socket(
            client_socket, server_hostname=self.server_host
        )
        print("🔒 [CLIENT] Secure connection established.")
        return secure_socket

    def send_credentials(self, secure_socket):
        """Prompt for username and password, then send them to the server."""
        username = input("Enter your username: ")
        password = input("Enter your password: ")

        credentials = json.dumps({"username": username, "password": password})
        secure_socket.send(credentials.encode("utf-8"))

        # Receive authentication response from the server
        response = secure_socket.recv(1024).decode("utf-8")
        print(response)
        return "Authentication successful" in response

    def send_blinded_message(self, input_message, secure_socket):
        """Send a blinded message for signing."""
        message = input_message
        blinded_message, r_inv = self.blind_message(message)

        if not blinded_message:
            print("⚠️ [CLIENT] Blinding failed, aborting.")
            return

        # Send blinded message to server
        request_data = json.dumps({"blinded_message": blinded_message})
        secure_socket.send(request_data.encode("utf-8"))

        # Receive and unblind signature
        response = secure_socket.recv(4096).decode("utf-8")
        response_data = json.loads(response)

        if "signature" in response_data:
            unblinded_signature = self.unblind_signature(
                response_data["signature"], r_inv
            )

            if unblinded_signature and self.verify_signature(
                message, unblinded_signature
            ):
                print(
                    f"✅ [CLIENT] Signature verified successfully: {unblinded_signature}"
                )
                self.save_message(message, unblinded_signature, True)
            else:
                print("⚠️ [CLIENT] Signature verification failed.")
        else:
            print(f"⚠️ [CLIENT] Error: {response_data.get('error')}")

    def fetch_messages_from_db(self):
        """Fetch stored messages from the SQLite database."""
        self.cur.execute("SELECT * FROM messages")
        messages = self.cur.fetchall()
        print("\n=== Stored Messages ===")
        for msg in messages:
            print(msg)

    def cast_vote(self):
        """Display candidates for political office and cast vote"""
        while True:
            print("\n=== Voting Menu ===")
            print("1. Hingle McCringleberry, East side")
            print("2. Donky Teeth, West side")
            print("3. Fudge, Fudge")
            print("4. Return")
            choice = input("Choose an option: ")

            if choice == "1":
                self.send_blinded_message("hingle_mccringleberry", self.secure_socket)
            elif choice == "2":
                self.send_blinded_message("donkey_teeth", self.secure_socket)
            elif choice == "3":
                self.send_blinded_message("fudge", self.secure_socket)
            elif choice == "4":
                print("Returning to main menu...")
                break
            else:
                print("Invalid choice. Please try again.")

    def show_menu(self):
        """Display the main menu and handle user input."""
        try:
            self.secure_socket = self.connect()  # Open connection once

            # Authenticate user
            if not self.send_credentials(self.secure_socket):
                print("⚠️ [CLIENT] Authentication failed. Exiting...")
                self.secure_socket.close()
                return

            while True:
                print("\n=== Secure Client Menu ===")
                print("1. Cast Vote")
                print("2. Fetch stored messages from the database")
                print("3. Exit")
                choice = input("Choose an option: ")

                if choice == "1":
                    self.cast_vote()
                elif choice == "2":
                    self.fetch_messages_from_db()
                elif choice == "3":
                    print("Exiting client...")
                    break
                else:
                    print("Invalid choice. Please try again.")
        except Exception as e:
            print(f"⚠️ [ERROR] {e}")
        finally:
            self.secure_socket.close()  # Close socket when done
