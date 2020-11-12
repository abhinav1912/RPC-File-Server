from helper_functions import *
import socket
import sys
import os
import time
import xmlrpc.client
import json

kdc_server = xmlrpc.client.ServerProxy('http://localhost:8000')
temp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
temp_socket.bind(('', 0))
print("Created new File Server at", temp_socket.getsockname())
address = temp_socket.getsockname()
temp_socket.close()

private_key = get_new_key()
public_key = private_key.public_key()
key = convert_private_key_to_bytes(private_key).decode()
print("Sending KDC a register message.")
server_number, server_key = kdc_server.register_server(address, convert_public_key_to_bytes(public_key))
server_key = server_key.data.decode()

print(f"File Server assigned number: {server_number}")
print(f"Launching FileServer{server_number}")
create_fileserver(server_number)
pwd = get_parent_path(__file__)
dest = os.path.join(pwd, f"FS{server_number}\\File_Server_Run.py")
temp_config = os.path.join(pwd, f"FS{server_number}/log.json")
with open(temp_config, 'r') as f:
    data = json.load(f)
    data["key"] = key
    data["server_key"] = server_key

os.remove(temp_config)
with open(temp_config, 'w') as f:
    json.dump(data, f, indent=4)
command = "start cmd /c C:/Python37/python.exe " + dest + " " + str(address[1])
if sys.platform == "linux":
    dest = os.path.join(pwd, f"FS{server_number}/File_Server_Run.py")
    command = "python3 " + dest + " " + str(address[1])

os.system(command)