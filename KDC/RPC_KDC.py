import json
import socket
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.client import ServerProxy
from KDC_helper_functions import *

server_address = get_server_address()
server_directory = {}
node_keys = {}
node_address = {}
node_temp_address = []
server_key = get_value("key")
logged_in_users = {}

if not server_key:
    private_key = get_new_key()
    public_key = private_key.public_key()
    pem = convert_private_key_to_bytes()
    update_config("key", pem.decode())
    fileservers = []
    addr_directory = {}
    fileserver_keys = {}
    users = {}

else:
    private_key = convert_bytes_to_private_key(str.encode(server_key))
    public_key = private_key.public_key()
    fileservers = get_value("fileservers")
    addr_directory = get_value("addr_directory")
    temp_keys = get_value("fileserver_keys")
    users = get_value("users")
    fileserver_keys = {i:convert_bytes_to_public_key(str.encode(temp_keys[i])) for i in temp_keys.keys()}

key_to_send = convert_public_key_to_bytes(public_key)

with SimpleXMLRPCServer(server_address) as server:
    server.register_introspection_functions()
    class KDC_Server:
        def test_server(self):
            print("TEST OUTPUT.")
            return 1

        def test_reg(self, key):
            print("New Key.")
            return public_key.decode()

        def register_server(self, address, key):
            '''
            Register new fileserver
            '''

            address = tuple(address)
            key = key.data
            print(f"New Register request from {address}")
            new_count = get_value("server")+1
            address = f'http://{address[0]}:{address[1]}'
            fileservers.append(address)
            update_config("fileservers", fileservers)
            addr_directory[new_count] = address
            server_directory[address] = new_count
            fileserver_keys[new_count] = convert_bytes_to_public_key(key)
            update_config("server", new_count)
            update_config("addr_directory", addr_directory)
            update_config(
                "fileserver_keys",
                {
                    i:convert_public_key_to_bytes(fileserver_keys[i]).decode() 
                    for i in fileserver_keys.keys()
                }
            )
            pop_list = []
            for i in node_temp_address:
                addr = f'http://127.0.0.1:{i[1]}'
                try:
                    node = ServerProxy(addr)
                    node.register_server(new_count)
                except:
                    pop_list.append(i)
            return new_count, key_to_send

        def register_file(self, server_number):
            '''
            Registers new file and updates all nodes
            '''

            new_count = get_value("file")+1
            pop_list = []
            update_config("file", new_count)
            for i in node_temp_address:
                addr = f'http://127.0.0.1:{i[1]}'
                try:
                    node = ServerProxy(addr)
                    node.register_file(f"file{new_count}.txt", server_number)
                except:
                    pop_list.append(i)
            for i in pop_list:
                node_temp_address.remove(i)
            return new_count

        def register_node(self, addr, temp_addr, key):
            '''
            Register a new distributed node
            '''
            node_count = get_value("nodes")+1
            node_keys[addr[1]] = convert_bytes_to_public_key(key.data)
            node_temp_address.append(temp_addr)
            addr = f'http://{addr[0]}:{addr[1]}'
            node_address[node_count] = addr
            node = ServerProxy(addr)
            node.test_server(server_address)
            update_config("nodes", node_count)
            return [node_count, key_to_send]
        
        def get_ls(self):
            '''
            Returns active fileservers
            '''
            ls = []
            for i in fileservers:
                try:
                    node = ServerProxy(i)
                    success = node.test_server(server_address)
                    ls.append(f"FS{success}")
                except Exception as error:
                    print(str(error))
                    success = 0
            return ls
        
        def is_authenticated(self, node, fileserver):
            '''
            Checks authentication of node with fileserver
            '''
            node = decrypt_message(private_key, node.data).decode()
            fileserver = decrypt_message(private_key, fileserver.data).decode()
            addr = addr_directory[fileserver]
            temp_key = fileserver_keys[fileserver]
            serv = ServerProxy(addr)
            try:
                temp_map = {"False":"0", "True":"1"}
                C = serv.is_node_authenticated(encrypt_message(temp_key, str.encode(node)))
                return temp_map[C]
            except:
                return "Fileserver down, try again later."
        
        def authenticate(self, node, fileserver, addr):
            '''
            Authenticates node with fileserver
            '''
            node = decrypt_message(private_key, node.data).decode()
            fileserver = decrypt_message(private_key, fileserver.data).decode()
            temp_key = node_keys[addr]
            fileserver_key = fileserver_keys[fileserver]
            fileserver_address = addr_directory[fileserver]
            new_key = create_symmetric_key()
            return (
                encrypt_message(temp_key, new_key),
                encrypt_message(fileserver_key, new_key),
                fileserver_address
            )
        
        def signup(self, node, username, password):
            '''
            Checks user credentials and signs them up
            '''
            username = decrypt_message(private_key, username.data).decode()
            password = decrypt_message(private_key, password.data).decode()
            if (node in logged_in_users.values()):
                return "User already logged into node"
            if (username in logged_in_users.keys()):
                return "User already logged into a different node"
            if username in users.keys():
                return "Username taken."
            users[username] = password
            update_config("users", users)
            logged_in_users[username] = node
            return "1"
        
        def login(self, node, username, password):
            '''
            Checks user credentials and logs them in
            '''
            username = decrypt_message(private_key, username.data).decode()
            password = decrypt_message(private_key, password.data).decode()
            if (node in logged_in_users.values()):
                return "User already logged into node"
            if (username in logged_in_users.keys()):
                try:
                    addr = node_address[logged_in_users[username]]
                    s = ServerProxy(addr)
                    s.test_server(server_address)
                    return "User already logged into a different node"
                except Exception:
                    del logged_in_users[username]
                    if users[username] == password:
                        logged_in_users[username] = node
                        return "1"
                    return "Incorrect password"
            if username not in users.keys():
                return "Invalid username."
            if users[username] == password:
                logged_in_users[username] = node
                return "1"
            return "Incorrect password"
        
        def logout(self, username):
            '''
            Checks user credentials and logs them out
            '''
            username = decrypt_message(private_key, username.data).decode()
            if username in logged_in_users.keys():
                del logged_in_users[username]
            return 1

        def test_encrypt(self, msg):
            message = decrypt_message(private_key, msg.data)
            print(type(message), message)
            
    server.register_instance(KDC_Server())
    server.serve_forever()