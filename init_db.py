import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect('app.db')
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user',
    email TEXT,
    secret_note TEXT
)''')

c.execute('''CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT,
    content TEXT
)''')

c.execute("INSERT OR IGNORE INTO users (id,login,password,role,email,secret_note) "
          "VALUES (1,'admin',?,'admin','admin@local','FLAG{admin_secret}')",
          (generate_password_hash('admin123'),))
c.execute("INSERT OR IGNORE INTO users (id,login,password,role,email,secret_note) "
          "VALUES (2,'alice',?,'user','alice@local','FLAG{alice_private}')",
          (generate_password_hash('alice123'),))
c.execute("INSERT OR IGNORE INTO users (id,login,password,role,email,secret_note) "
          "VALUES (3,'bob',?,'user','bob@local','FLAG{bob_private}')",
          (generate_password_hash('bob123'),))

c.execute("INSERT OR IGNORE INTO notes (id,user_id,title,content) VALUES (1,2,'Alice note','private alice data')")
c.execute("INSERT OR IGNORE INTO notes (id,user_id,title,content) VALUES (2,3,'Bob note','private bob data')")

conn.commit(); conn.close()
print('DB initialized (secure hashes)')