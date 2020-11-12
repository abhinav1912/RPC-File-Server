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
if not server_key:
    private_key = get_new_key()
    public_key = private_key.public_key()
    pem = convert_private_key_to_bytes()
    update_config("key", pem.decode())
    fileservers = []
    addr_directory = {}
    fileserver_keys = {}

else:
    private_key = convert_bytes_to_private_key(str.encode(server_key))
    public_key = private_key.public_key()
    fileservers = get_value("fileservers")
    addr_directory = get_value("addr_directory")
    temp_keys = get_value("fileserver_keys")
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
    
        # def test_reg2(msg, key):

        def adder_function(self, x, y):
            # x,y = x.data, y.data
            # x = f.decrypt(x).decode()
            # y = f.decrypt(y).decode()
            
            # return int(x) + int(y)
            return x+y

        def register_server(self, address, key):
            address = tuple(address)
            key = key.data
            print(f"New Register request from {address}")
            new_count = get_value("server")+1
            address = f'http://{address[0]}:{address[1]}'
            fileservers.append(address)
            update_config("fileservers", fileservers)
            addr_directory[new_count] = address
            print(address)
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
            return new_count, key_to_send

        def register_file(self, server_number):
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
            
            node_count = get_value("nodes")+1
            node_keys[addr[1]] = convert_bytes_to_public_key(key.data)
            node_temp_address.append(temp_addr)
            addr = f'http://{addr[0]}:{addr[1]}'
            # print("WORKS1")
            node = ServerProxy(addr)
            node.test_server(server_address)
            update_config("nodes", node_count)
            # print("WORKS2")
            return [node_count, key_to_send]
        
        def get_ls(self, curr_dir):
            curr_dir = decrypt_message(private_key, curr_dir.data).decode()
            ls = []
            if curr_dir == "/root":
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
            node = decrypt_message(private_key, node.data).decode()
            fileserver = decrypt_message(private_key, fileserver.data).decode()
            addr = addr_directory[fileserver]
            temp_key = fileserver_keys[fileserver]
            serv = ServerProxy(addr)
            try:
                temp_map = {"False":"0", "True":"1"}
                return temp_map[serv.is_node_authenticated(encrypt_message(temp_key, str.encode(node)))]
            except:
                return "Fileserver down, try again later."
        
        def authenticate(self, node, fileserver, addr):
            node = decrypt_message(private_key, node.data).decode()
            fileserver = decrypt_message(private_key, fileserver.data).decode()
            temp_key = node_keys[addr]
            fileserver_key = fileserver_keys[fileserver]
            fileserver_address = addr_directory[fileserver]
            new_key = create_symmetric_key()
            m1 = encrypt_message(fileserver_key, new_key)
            print("fff", temp_key, "CCCCCCCCCCCCC",m1)
            m2 = encrypt_message(temp_key, m1)
            print("m2")
            return (
                encrypt_message(temp_key, new_key),
                encrypt_message(temp_key, encrypt_message(fileserver_key, new_key)),
                fileserver_address
            )

        def test_encrypt(self, msg):
            message = decrypt_message(private_key, msg.data)
            print(type(message), message)
            
    server.register_instance(KDC_Server())
    server.serve_forever()