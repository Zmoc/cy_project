from config import CERT_FILE, KEY_FILE, SERVER_PORT, SERVER_PRIVATE_KEY, USER_DB
from src.classes.ca_server import SecureServer

ca_server = SecureServer(
    host="0.0.0.0",
    port=SERVER_PORT,
    certfile=CERT_FILE,
    keyfile=KEY_FILE,
    private_key=SERVER_PRIVATE_KEY,
    db_path=USER_DB,
)

ca_server.start()
