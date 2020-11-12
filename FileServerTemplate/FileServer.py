import sys    
import os
import socket
import json
from pathlib import Path
from cryptography.fernet import Fernet
import xmlrpc.client


pwd = Path(__file__).parent.absolute()
filename = os.path.join(pwd, "log.json")
with open(filename, 'r') as f:
    data = json.load(f)
    addr, port = data["kdcIP"], data["kdcPort"]

serv_add = f'http://{addr}:{port}'
print(serv_add)
kdc = xmlrpc.client.ServerProxy(serv_add)
def get_parent_path():
    return Path(__file__).parent.absolute()

def update_log(key, count):
    
    with open(filename, 'r') as f:
        data = json.load(f)
        data[key] = count

    os.remove(filename)
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def start_server():
    pwd = Path(__file__).parent.absolute()
    filename = os.path.join(pwd, "log.json")
    with open(filename, 'r') as f:
        data = json.load(f)
        port = data["port"]
        key = data["key"]
    if not port:
        port = int(sys.argv[1])
        key = sys.argv[2]
        update_log("port", port)
        update_log("key", key)
    return str.encode(key)

def create_files():
    n = int(input("Enter the number of files to create: "))
    for i in range(n):
        print(f"Creating new file")
        x = int(input("Do you want to add text (0/1): "))
        text = ""
        if x:
            text = input("Enter text: ")
        file_count = kdc.register_file()
        new_file = os.path.join(pwd, f"file{file_count}.txt")
        with open(new_file, 'w') as file:
            if text:
                file.write(text)
        update_log("files", file_count)
        print(f"file{file_count}.txt created.")

key = start_server()
crypt = Fernet(key)
server_number = str(pwd).split("/FS")[-1]
print(f"[+] Fileserver {server_number} running")
success = kdc.test_server()
if not success:
    print("Connection to server wasn't established.\nExiting now.")
    os.exit(1)
create_files()

while True:
    n = input()
