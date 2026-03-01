#!/usr/bin/env python3
"""
Simple vulnerable web application for testing WAF payload detection
Simulates common vulnerabilities for testing purposes
WARNING: This is intentionally vulnerable - DO NOT deploy to production!
"""

from flask import Flask, request, render_template_string, make_response
import sqlite3
import os

app = Flask(__name__)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('test_db.sqlite')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123')")
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return '''
    <html>
    <head><title>Test Vulnerable Application</title></head>
    <body>
        <h1>Test Vulnerable Application</h1>
        <p>This is a test application for WAF payload testing</p>
        <ul>
            <li><a href="/search?q=test">Search (XSS vulnerable)</a></li>
            <li><a href="/login">Login (SQLi vulnerable)</a></li>
            <li><a href="/api/user?id=1">API Endpoint</a></li>
        </ul>
    </body>
    </html>
    '''

@app.route('/search')
def search():
    """Intentionally vulnerable to XSS"""
    query = request.args.get('q', '')
    # VULNERABLE: No sanitization
    html = f'''
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h1>Search Results for: {query}</h1>
        <p>Your search: {query}</p>
        <a href="/">Back</a>
    </body>
    </html>
    '''
    return html

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Intentionally vulnerable to SQL Injection"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # VULNERABLE: SQL Injection
        conn = sqlite3.connect('test_db.sqlite')
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        
        try:
            cursor.execute(query)
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return f'<h1>Login Successful!</h1><p>Welcome {result[1]}</p><a href="/">Back</a>'
            else:
                return '<h1>Login Failed</h1><p>Invalid credentials</p><a href="/login">Try again</a>'
        except Exception as e:
            conn.close()
            return f'<h1>Error</h1><p>{str(e)}</p><a href="/login">Back</a>'
    
    return '''
    <html>
    <body>
        <h1>Login</h1>
        <form method="POST">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
        <a href="/">Back</a>
    </body>
    </html>
    '''

@app.route('/api/user')
def api_user():
    """API endpoint"""
    user_id = request.args.get('id', '1')
    
    # VULNERABLE: SQL Injection
    conn = sqlite3.connect('test_db.sqlite')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id={user_id}"
    
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {'id': result[0], 'username': result[1]}
        else:
            return {'error': 'User not found'}, 404
    except Exception as e:
        conn.close()
        return {'error': str(e)}, 500

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    """Comment form - vulnerable to XSS"""
    if request.method == 'POST':
        comment_text = request.form.get('comment', '')
        # VULNERABLE: No sanitization
        return f'''
        <html>
        <body>
            <h1>Your Comment</h1>
            <div>{comment_text}</div>
            <a href="/comment">Add another</a> | <a href="/">Home</a>
        </body>
        </html>
        '''
    
    return '''
    <html>
    <body>
        <h1>Add Comment</h1>
        <form method="POST">
            <textarea name="comment" rows="5" cols="50"></textarea><br>
            <input type="submit" value="Submit">
        </form>
        <a href="/">Back</a>
    </body>
    </html>
    '''

if __name__ == '__main__':
    print('=' * 80)
    print('VULNERABLE TEST APPLICATION')
    print('=' * 80)
    print('WARNING: This application is intentionally vulnerable!')
    print('DO NOT expose this to the internet or use in production!')
    print('')
    print('Starting server on http://127.0.0.1:5000')
    print('Press Ctrl+C to stop')
    print('=' * 80)
    app.run(host='127.0.0.1', port=5000, debug=False)
