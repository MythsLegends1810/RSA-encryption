import subprocess
import json
import os
from functools import wraps
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

BACKEND_BINARY = "/app/backend"

def find_backend():
    candidates = [
        os.environ.get("BACKEND_BINARY"),
        "/app/backend",
        os.path.join(os.path.dirname(__file__), "..", "backend"),
        os.path.join(os.path.dirname(__file__), "..", "backend.exe"),
        os.path.join(os.getcwd(), "backend"),
        os.path.join(os.getcwd(), "backend.exe"),
        "./backend",
        "./backend.exe",
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return "/app/backend"

def run_backend(command, *args):
    backend = find_backend()
    if not os.path.exists(backend):
        raise Exception(f"Backend binary not found at {backend}")
    cmd = [backend, command] + [str(a) for a in args]
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
        return jsonify({"error": stderr or "Failed to generate keys"}), 500
    return jsonify(parse_output(stdout))

@app.route('/api/encrypt', methods=['POST'])
@api_safe
def encrypt():
    data = request.get_json() or {}
    message = data.get('message', '')
    if not message:
        return jsonify({"error": "Message required"}), 400
    e = str(data.get('e', '')).strip()
    n = str(data.get('n', '')).strip()
    if e and n:
        code, stdout, stderr = run_backend("encrypt", message, e, n)
    else:
        code, stdout, stderr = run_backend("encrypt", message)
    if code != 0:
        return jsonify({"error": stderr or "Encryption failed"}), 500
    return jsonify(parse_output(stdout))

@app.route('/api/decrypt', methods=['POST'])
@api_safe
def decrypt():
    data = request.get_json() or {}
    encrypted = str(data.get('encrypted', '')).strip()
    if not encrypted:
        return jsonify({"error": "Encrypted message required"}), 400
    
    d = str(data.get('d', '')).strip()
    n = str(data.get('n', '')).strip()
    p = str(data.get('p', '')).strip()
    q = str(data.get('q', '')).strip()
    
    # If P and Q are provided instead of D and N, derive D and N mathematically
    if not d and not n and p and q:
        try:
            p_int = int(p)
            q_int = int(q)
            e_val = data.get('e', 65537) or 65537
            e_int = int(e_val)
            n_int = p_int * q_int
            t_int = (p_int - 1) * (q_int - 1)
            d_int = pow(e_int, -1, t_int)
            d = str(d_int)
            n = str(n_int)
        except Exception as ex:
            return jsonify({"error": f"Failed to compute private key from P and Q: {str(ex)}"}), 400

    if d and n:
        code, stdout, stderr = run_backend("decrypt", encrypted, d, n)
    else:
        code, stdout, stderr = run_backend("decrypt", encrypted)

    if code != 0:
        return jsonify({"error": stderr or "Decryption failed"}), 500
    return jsonify(parse_output(stdout))

@app.route('/api/sign', methods=['POST'])
@api_safe
def sign():
    data = request.get_json() or {}
    message = data.get('message', '')
    if not message:
        return jsonify({"error": "Message required"}), 400
    d = str(data.get('d', '')).strip()
    n = str(data.get('n', '')).strip()
    if d and n:
        code, stdout, stderr = run_backend("sign", message, d, n)
    else:
        code, stdout, stderr = run_backend("sign", message)
    if code != 0:
        return jsonify({"error": stderr or "Signing failed"}), 500
    return jsonify(parse_output(stdout))

@app.route('/api/verify', methods=['POST'])
@api_safe
def verify():
    data = request.get_json() or {}
    message = data.get('message', '')
    signature = str(data.get('signature', '')).strip()
    if not message or not signature:
        return jsonify({"error": "Message and signature required"}), 400
    n = str(data.get('n', '')).strip()
    e = str(data.get('e', '')).strip()
    if n and e:
        code, stdout, stderr = run_backend("verify", message, signature, n, e)
    elif n:
        code, stdout, stderr = run_backend("verify", message, signature, n)
    else:
        code, stdout, stderr = run_backend("verify", message, signature)
    if code != 0:
        return jsonify({"error": stderr or "Verification failed"}), 500
    return jsonify(parse_output(stdout))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)