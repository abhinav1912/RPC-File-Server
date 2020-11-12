import os
import shutil
import json
import socket
from pathlib import Path
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def get_parent_path(__file__):
    return Path(__file__).parent.absolute()

def get_current_path(__file__):
    return Path(__file__).absolute()

def remove_servers():
    pwd = os.getcwd()
    l = os.listdir()
    for i in l:
        if len(i)>2 and i[:2]=="FS":
            path = os.path.join(pwd, i)
            shutil.rmtree(path)

def get_count(key):
    keymap = {"server" : "server_count", "file" : "file_count"}
    key = keymap[key]
    temp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    send_kdc_message(temp_socket, f"GET_COUNT {key}")
    connection = temp_socket.recvfrom(buffer_size)
    message = connection[0].decode()
    temp_socket.close()
    return int(message)

def create_fileserver(i):
    fileserver_run_script = "File_Server_Run.py"
    pwd = get_parent_path(__file__)
    name = "FS" + str(i)
    path = os.path.join(pwd, name)
    os.mkdir(path)
    pwd = os.path.join(pwd, "FileServerTemplate")
    for i in os.listdir(pwd):
        src = os.path.join(pwd, i)
        dest = os.path.join(path, i)
        shutil.copyfile(src, dest)

def create_files(server_number, path):
    n = int(input(f"Enter number of files for server FS{server_number} : "))
    file_count = get_count("file")
    for count in range(0, n):
        temp_path = os.path.join(path, f"file{file_count+count+1}.txt")
        with open(temp_path, 'w+'):
            pass

def get_kdc_address():
    filename = "config.json"
    with open(filename, 'r') as f:
        data = json.load(f)
        return (data["kdcIP"], data["kdcPort"])

def send_kdc_message(sender_socket, message):
    buffer_size = 1024
    byte_form = str.encode(message)
    sender_socket.sendto(byte_form, server_address)

server_address = get_kdc_address()

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