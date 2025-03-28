import sqlite3


class Voter_Server:
    def __init__(self, db_path):
        self.db_path = db_path
        self.con = sqlite3.connect(database=self.db_path)
        self.cur = self.con.cursor()

    def __path__(self):
        return f"{self.db_path}"

    def cursor(self):
        return self.cur


# Record (id, first_name,last_name,fing_hash)
