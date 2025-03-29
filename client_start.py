from src.classes.v_client import Voter_Client

client = Voter_Client(
    server_host="127.0.0.1",
    server_port="12345",
    certfile="certs/server.crt",
    public_key="certs/server_public.pem",
    db_path="data/db/fing_hash.db",
)

client.connect()
