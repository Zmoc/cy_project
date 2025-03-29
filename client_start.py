from config import CERT_FILE, DB_PATH, SERVER_HOST, SERVER_PORT, SERVER_PUBLIC_KEY
from src.classes.v_client import Voter_Client

client = Voter_Client(
    host=SERVER_HOST,
    port=SERVER_PORT,
    certfile=CERT_FILE,
    public_key=SERVER_PUBLIC_KEY,
    db_path=DB_PATH,
)

client.connect()
