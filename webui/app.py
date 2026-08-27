import subprocess
import json
import os
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Path to the compiled C++ backend
BACKEND_BINARY = "/app/backend"

def compile_backend():
    """Compile the C++ backend if not already compiled"""
    if not os.path.exists(BACKEND_BINARY):
        result = subprocess.run([
            "g++", "-std=c++17", "-O2", "-I/workspace",
            "-o", BACKEND_BINARY, "/workspace/backend_server.cpp"
        ], capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Failed to compile backend: {result.stderr}")

def run_backend(command, *args):
    """Run the backend binary with given command and args"""
    compile_backend()
    cmd = [BACKEND_BINARY, command] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr

def parse_output(output):
    """Parse key:value output from backend"""
    data = {}
    for line in output.strip().split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            data[key.strip()] = value.strip()
    return data

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/generate', methods=['POST'])
def generate_keys():
    code, stdout, stderr = run_backend("gen")
    if code != 0:
        return jsonify({"error": stderr}), 500
    return jsonify(parse_output(stdout))

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    message = data.get('message', '')
    if not message:
        return jsonify({"error": "Message required"}), 400
    
    code, stdout, stderr = run_backend("encrypt", message)
    if code != 0:
        return jsonify({"error": stderr}), 500
    return jsonify(parse_output(stdout))

@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    encrypted = data.get('encrypted', '')
    p = data.get('p', '')
    q = data.get('q', '')
    if not encrypted or not p or not q:
        return jsonify({"error": "Encrypted message, P, and Q required"}), 400
    
    code, stdout, stderr = run_backend("decrypt", encrypted, p, q)
    if code != 0:
        return jsonify({"error": stderr}), 500
    return jsonify(parse_output(stdout))

@app.route('/api/sign', methods=['POST'])
def sign():
    data = request.get_json()
    message = data.get('message', '')
    if not message:
        return jsonify({"error": "Message required"}), 400
    
    code, stdout, stderr = run_backend("sign", message)
    if code != 0:
        return jsonify({"error": stderr}), 500
    return jsonify(parse_output(stdout))

@app.route('/api/verify', methods=['POST'])
def verify():
    data = request.get_json()
    message = data.get('message', '')
    signature = data.get('signature', '')
    n = data.get('n', '')
    if not message or not signature or not n:
        return jsonify({"error": "Message, signature, and N required"}), 400
    
    code, stdout, stderr = run_backend("verify", message, signature, n)
    if code != 0:
        return jsonify({"error": stderr}), 500
    return jsonify(parse_output(stdout))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)