"""Simple vulnerable Flask app for Docker image testing."""

from flask import Flask, request
import os

app = Flask(__name__)

# Hardcoded secret (should be detected)
SECRET_KEY = "hardcoded-secret-key-12345"

@app.route('/')
def hello():
    return "Vulnerable Test App"

@app.route('/env')
def show_env():
    # Unsafe: exposing environment variables
    return str(dict(os.environ))

if __name__ == '__main__':
    # Unsafe: debug mode in production
    app.run(host='0.0.0.0', port=5000, debug=True)
