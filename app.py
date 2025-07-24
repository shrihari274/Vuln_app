from flask import Flask, request
import os

# Simulate malicious activity
os.system("curl http://malicious.example.com")  # Dummy malicious activity

app = Flask(__name__)

# Example of hardcoded secret (vulnerability)
API_KEY = "hardcoded_secret_123"

@app.route('/')
def home():
    return "Welcome to Vulnerable App!"

@app.route('/ping')
def ping():
    return "pong"

@app.route('/vuln')
def vuln():
    user_input = request.args.get("input", "")
    return f"You entered: {user_input}"

@app.route('/malicious')
def malicious():
    # This is just to simulate command injection
    user_input = request.args.get("cmd", "")
    os.system(user_input)  # Very vulnerable!
    return "Command executed (vulnerable)"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

