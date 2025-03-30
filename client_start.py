from config import CERT_FILE, FING_DB, SERVER_HOST, SERVER_PORT, SERVER_PUBLIC_KEY
from src.classes.v_client import SecureClient

client = SecureClient(
    server_host=SERVER_HOST,
    server_port=SERVER_PORT,
    certfile=CERT_FILE,
    public_key=SERVER_PUBLIC_KEY,
    db_path=FING_DB,
)

client.show_menu()
