import sys
import os
import socket
import json
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet, InvalidToken

def get_parent_path(__file__):
    return Path(__file__).parent.absolute()

def get_current_path(__file__):
    return Path(__file__).absolute()

curr_dir = get_parent_path(__file__) 
filename = os.path.join(curr_dir, "KDC_config.json")

def get_value(key):
    if key in ["server", "file"]:
        keymap = {"server" : "server_count", "file" : "file_count"}
        key = keymap[key]
    with open(filename, 'r') as f:
        data = json.load(f)
        return data[key]

def get_server_address():
    with open(filename, 'r') as f:
        data = json.load(f)
        return (data["kdcIP"], data["kdcPort"])

def update_config(key, count):
    if key in ["server", "file"]:
        keymap = {"server" : "server_count", "file" : "file_count"}
        key = keymap[key]
    with open(filename, 'r') as f:
        data = json.load(f)
        data[key] = count

    os.remove(filename)
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def send_reply(temp_socket, message, address):
    byte_form = str.encode(message)
    temp_socket.sendto(byte_form, address)

def get_new_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )

def convert_private_key_to_bytes(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def convert_public_key_to_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def convert_bytes_to_public_key(byte_form):
    return serialization.load_pem_public_key(
        byte_form,
        backend=default_backend()
    )

def convert_bytes_to_private_key(byte_form):
    return serialization.load_pem_private_key(
        byte_form,
        password=None,
        backend=default_backend()
    )

def encrypt_message(key, message):
    return key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_message(key, message):
    return key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def create_symmetric_key():
    return Fernet.generate_key()