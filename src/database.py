import sqlite3

DATABASE = "../database/sql.db"

class Database:

    def __init__(self, database=DATABASE):
        self._database = database
        self._conn = None
        self._cursor = None

    @property
    def conn(self):
        return self._conn

    @property
    def cursor(self):
        return self._cursor

    def connect(self):
        self._conn = sqlite3.connect(self._database, check_same_thread=False)
        self._cursor = self._conn.cursor()

    def user(self, key):
        result = self._cursor.execute(f"SELECT * FROM users where key = ?", (key, )).fetchone()
        return result

    def user_blocklists(self, user_id):
        blocklists = self._cursor.execute("SELECT * FROM user_blocklists WHERE id = ?", (user_id, )).fetchone()
        return blocklists[1]

    def is_in_blocklist(self, blocklist, tld):
        result = self._cursor.execute("SELECT url from blocklist_entries WHERE blocklist_id = ? AND url = ?", 
            (blocklist, tld)).fetchone()
        return result is not None

    def is_blocked(self, key, tld):
        user = self.user(key)

        # if ID is invalid then we just assume nothing is blocked
        if not user:
            return False

        user_id = user[0]

        blocklists = self.user_blocklists(user_id)

        for blocklist in blocklists.split(","):
            if self.is_in_blocklist(blocklist, tld):
                return True

        return False
