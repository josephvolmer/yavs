"""Sample vulnerable Python code for testing SAST scanners."""

import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)


# SQL Injection vulnerability
def get_user(username):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Unsafe: SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()


# Command Injection vulnerability
def run_command(cmd):
    # Unsafe: command injection
    os.system(cmd)


# Hardcoded credentials
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
PASSWORD = "admin123"


# Insecure random
import random
def generate_token():
    # Unsafe: insecure random for security purposes
    return str(random.randint(1000, 9999))


# Path traversal
@app.route('/read')
def read_file():
    filename = request.args.get('file')
    # Unsafe: path traversal vulnerability
    with open(filename, 'r') as f:
        return f.read()


# Eval injection
def calculate(expression):
    # Unsafe: code injection via eval
    return eval(expression)


if __name__ == '__main__':
    # Unsafe: debug mode enabled
    app.run(debug=True, host='0.0.0.0')
