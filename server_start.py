from config import CERT_FILE, KEY_FILE, SERVER_PORT, SERVER_PRIVATE_KEY
from src.classes.server import SecureServer

ca_server = SecureServer(
    host="0.0.0.0",
    port=SERVER_PORT,
    certfile=CERT_FILE,
    keyfile=KEY_FILE,
    private_key=SERVER_PRIVATE_KEY,
)

ca_server.start()
