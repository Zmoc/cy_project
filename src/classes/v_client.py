import sqlite3

from src.classes.client import SecureClient


class Voter_Client(SecureClient):
    def __init__(self, host, port, certfile, public_key, db_path):
        super().__init__(host, port, certfile, public_key)
        self.db_path = db_path
        self.con = sqlite3.connect(database=self.db_path)
        self.cur = self.con.cursor()

    def __path__(self):
        return f"{self.db_path}"

    def cursor(self):
        return self.cur

    def message(self):
        message = input("Enter message (type 'exit' to quit): ")
        return message


# Record (id, first_name,last_name,fing_hash)
