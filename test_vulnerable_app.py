
from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import os

app = Flask(__name__)

# Initialize a simple SQLite database
def init_db():
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123', 'admin@test.com')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'user123', 'user@test.com')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (3, 'guest', 'guest123', 'guest@test.com')")
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return '''
    <h1>Test Vulnerable Application</h1>
    <p>This app contains intentional vulnerabilities for testing purposes.</p>
    <ul>
        <li><a href="/search?query=test">Search (SQL Injection)</a></li>
        <li><a href="/profile?id=1">User Profile (IDOR)</a></li>
        <li><a href="/comment?msg=Hello">Comment (XSS)</a></li>
        <li><a href="/login">Login Form</a></li>
        <li><a href="/file?name=test.txt">File Access</a></li>
    </ul>
    '''

# SQL Injection vulnerability
@app.route('/search')
def search():
    query = request.args.get('query', '')
    if query:
        conn = sqlite3.connect('test.db')
        cursor = conn.cursor()
        # Intentionally vulnerable SQL query
        sql = f"SELECT * FROM users WHERE username LIKE '%{query}%'"
        try:
            cursor.execute(sql)
            results = cursor.fetchall()
            conn.close()
            return f"<h2>Search Results for: {query}</h2><pre>{results}</pre>"
        except Exception as e:
            conn.close()
            return f"<h2>Error:</h2><pre>{str(e)}</pre>"
    return "<h2>Search</h2><form><input name='query' placeholder='Enter search term'><button>Search</button></form>"

# IDOR vulnerability
@app.route('/profile')
def profile():
    user_id = request.args.get('id', '1')
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return f"<h2>User Profile</h2><p>ID: {user[0]}<br>Username: {user[1]}<br>Email: {user[3]}</p>"
    return "User not found"

# XSS vulnerability
@app.route('/comment')
def comment():
    msg = request.args.get('msg', '')
    # Intentionally vulnerable - no escaping
    return f"<h2>Comment</h2><p>You said: {msg}</p><form><input name='msg' placeholder='Enter comment'><button>Submit</button></form>"

# Command injection vulnerability
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    if host:
        # Intentionally vulnerable command injection
        import subprocess
        try:
            result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
            return f"<h2>Ping Results</h2><pre>{result}</pre>"
        except Exception as e:
            return f"<h2>Error:</h2><pre>{str(e)}</pre>"
    return "<h2>Ping Tool</h2><form><input name='host' placeholder='Enter hostname'><button>Ping</button></form>"

# File inclusion vulnerability
@app.route('/file')
def read_file():
    filename = request.args.get('name', '')
    if filename:
        try:
            # Intentionally vulnerable file inclusion
            with open(filename, 'r') as f:
                content = f.read()
            return f"<h2>File Contents</h2><pre>{content}</pre>"
        except Exception as e:
            return f"<h2>Error:</h2><pre>{str(e)}</pre>"
    return "<h2>File Reader</h2><form><input name='name' placeholder='Enter filename'><button>Read</button></form>"

# Login form for testing
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect('test.db')
        cursor = conn.cursor()
        # Vulnerable SQL query for authentication
        sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(sql)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return f"<h2>Welcome {user[1]}!</h2><p>Login successful</p>"
        else:
            return "<h2>Login Failed</h2><p>Invalid credentials</p>"
    
    return '''
    <h2>Login</h2>
    <form method="post">
        <p>Username: <input name="username"></p>
        <p>Password: <input name="password" type="password"></p>
        <p><button>Login</button></p>
    </form>
    '''

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=3000, debug=True)
