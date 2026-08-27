import subprocess
import json
import os
from functools import wraps
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

BACKEND_BINARY = "/app/backend"

def run_backend(command, *args):
    if not os.path.exists(BACKEND_BINARY):
        raise Exception(f"Backend binary not found at {BACKEND_BINARY}")
    cmd = [BACKEND_BINARY, command] + list(args)
    print(f"[DEBUG] Running: {' '.join(cmd)}", flush=True)
    result = subprocess.run(cmd, capture_output=True)
    stdout = result.stdout.decode('utf-8', errors='replace')
    stderr = result.stderr.decode('utf-8', errors='replace')
    print(f"[DEBUG] Exit code: {result.returncode}", flush=True)
    if stdout:
        print(f"[DEBUG] stdout: {stdout[:500]}", flush=True)
    if stderr:
        print(f"[DEBUG] stderr: {stderr[:500]}", flush=True)
    return result.returncode, stdout, stderr

def parse_output(output):
    data = {}
    for line in output.strip().split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            data[key.strip()] = value.strip()
    return data

def api_safe(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return wrapper

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/api/generate', methods=['POST'])
@api_safe
def generate_keys():
    code, stdout, stderr = run_backend("gen")
    if code != 0:
        return jsonify({"error": stderr}), 500
    return jsonify(parse_output(stdout))

@app.route('/api/encrypt', methods=['POST'])
@api_safe
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
@api_safe
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
@api_safe
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
@api_safe
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