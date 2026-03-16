import sqlite3

def get_user(user_id):
    # SEC002 — SQL injection via taint
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()

def search(query):
    # SEC002 — string concatenation
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name = '" + query + "'")
    return cursor.fetchall()