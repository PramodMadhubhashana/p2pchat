import os
import hashlib
import base64
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import bleach

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app)

# Symmetric key for AES encryption (should be securely shared between clients)
SYMMETRIC_KEY = os.urandom(32)  # 256-bit key

def encrypt_message(message):
    iv = os.urandom(16)  # 128-bit IV
    cipher = Cipher(algorithms.AES(SYMMETRIC_KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()

def decrypt_message(encrypted_message):
    encrypted_data = base64.b64decode(encrypted_message)
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(SYMMETRIC_KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode()

def compute_hash(message):
    sha256 = hashlib.sha256()
    sha256.update(message.encode())
    return sha256.hexdigest()

def validate_input(message):
    cleaned_message = bleach.clean(message, strip=True)
    if len(cleaned_message) > 500:
        raise ValueError("Input too long")
    return cleaned_message

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/chat')
def chat():
    return render_template('chat.html')

@app.route('/decrypt_message', methods=['POST'])
def decrypt_message_endpoint():
    try:
        data = request.json
        encrypted_message = data['message']
        received_hash = data['hash']

        decrypted_message = decrypt_message(encrypted_message)
        computed_hash = compute_hash(decrypted_message)
        if received_hash != computed_hash:
            raise ValueError("Message integrity compromised")

        return jsonify({'message': decrypted_message})
    except Exception as e:
        return jsonify({'error': str(e)})

@socketio.on('join')
def handle_join(data):
    room = data['room']
    join_room(room)
    emit('status', {'msg': f'{data["username"]} has joined the room.'}, room=room)

@socketio.on('leave')
def handle_leave(data):
    room = data['room']
    leave_room(room)
    emit('status', {'msg': f'{data["username"]} has left the room.'}, room=room)

@socketio.on('send_message')
def handle_send_message(data):
    try:
        room = data['room']
        username = validate_input(data['username'])
        message = validate_input(data['message'])

        encrypted_message = encrypt_message(message)
        message_hash = compute_hash(message)

        emit('display_message', {
            'username': username,
            'message': encrypted_message,
            'hash': message_hash
        }, room=room)
    except Exception as e:
        emit('error', {'error': str(e)})

if __name__ == '__main__':
    socketio.run(app, debug=True)
