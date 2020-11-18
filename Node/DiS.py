import os
import sys
import socket
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.client import ServerProxy
from pathlib import Path
import datetime
import json
import logging
import signal
import time
import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk, VERTICAL, HORIZONTAL, N, S, E, W
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet, InvalidToken

def get_parent_path():
    return Path(__file__).parent.absolute()

def prints(msg):
    server_queue.append(msg)

def printc(msg):
    console_queue.append(msg)

def start_server():
    temp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    temp_socket.bind(('', 0))
    address = temp_socket.getsockname()
    return address

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

class ConsoleUi:
    """Poll messages from a logging queue and display them in a scrolled text widget"""

    def __init__(self, frame, queue):
        self.frame = frame
        self.queue = queue
        self.scrolled_text = ScrolledText(frame, state='disabled', height=12)
        self.scrolled_text.grid(row=0, column=0, sticky=(N, S, W, E))
        self.scrolled_text.configure(font='TkFixedFont')
        self.scrolled_text.tag_config('INFO', foreground='black')
        self.scrolled_text.tag_config('BLUE', foreground='blue')
        self.scrolled_text.tag_config('ORANGE', foreground='orange')
        self.scrolled_text.tag_config('RED', foreground='red')
        self.command_queue = []
        self.curr_files = []
        self.is_command = 0
        self.is_logged_in = 0
        self.username = ""
        self.curr_dir = "/root"
        self.callables = {
            "cd": self.cd,
            "cp": self.cp,
            "pwd": self.pwd,
            "cat": self.cat,
            "ls": self.ls,
            "login": self.login,
            "logout": self.logout,
            "signup": self.signup
        }
        self.frame.after(100, self.poll_log_queue)

    def display(self, record, style = 'INFO', is_user = None):
        '''
        Display the given text with selected formatting
        '''

        self.scrolled_text.configure(state='normal')
        if is_user:
            self.scrolled_text.insert(tk.END, str(record) + '\n', style)
        else:
            self.scrolled_text.insert(tk.END, ">>> " + str(record) + '\n', style)
        self.scrolled_text.configure(state='disabled')
        self.scrolled_text.yview(tk.END)

    def poll_log_queue(self):
        '''
        Retrieve messages from queue
        '''

        while True:
            if not self.queue:
                break
            else:
                record = self.queue[0]
                del self.queue[0]
                if record.lower() in self.callables.keys() and not self.is_command:
                    self.is_command = 1
                    self.display(record)
                    temp_thread = threading.Thread(target=self.callables[record.lower()])
                    temp_thread.start()
                elif self.is_command:
                    self.command_queue.append(record)
                else:
                    self.display(record)
        self.frame.after(500, self.poll_log_queue)
        
    def cd(self):
        '''
        Functionality to change directory
        '''

        self.display("Available Directories: ")
        self.ls()
        self.is_command = 1
        self.display("Enter the directory")
        dest = self.wait_for_input(str)
        if dest == "root":
            self.curr_dir = "/root"
            self.display(f"Now in directory {self.curr_dir}", True)
        elif dest not in self.curr_files:
            self.display("Directory not found", "RED")
        else:
            fileserver_number = dest.split("FS")[1]
            auth = kdc.is_authenticated(
                encrypt_message(server_key, str.encode(str(node_number))),
                encrypt_message(server_key, str.encode(fileserver_number))
            )
            if auth == "1":
                self.curr_dir += f"/FS{fileserver_number}"
                self.display(f"Now in directory {self.curr_dir}", True)
            elif auth == "0":
                self.display("Server needs to authenticate Node.", "RED")
                self.display("Attempting authentication.", "BLUE")
                new_key, temp_key, fileserver_addr = kdc.authenticate(
                    encrypt_message(server_key, str.encode(str(node_number))),
                    encrypt_message(server_key, str.encode(fileserver_number)),
                    my_addr[1]
                )
                new_key = decrypt_message(private_key, new_key.data)
                fileserver = ServerProxy(fileserver_addr)
                nonce = fileserver.authenticate(node_number, temp_key).data
                f = Fernet(new_key)
                nonce = int((f.decrypt(nonce)).decode())
                is_auth = fileserver.confirm_auth(node_number, f.encrypt(str.encode(str(nonce-1))))
                if is_auth:
                    fileserver_keys[fileserver_number] = new_key
                    fileserver_addresses[fileserver_number] = fileserver_addr
                    self.display(f"Node is now authenticated with FS{fileserver_number}")
                    self.curr_dir += f"/FS{fileserver_number}"
                    self.display(f"Now in dir {self.curr_dir}", "BLUE", True)
                else:
                    self.display("Authentication failed.", "RED")
            else:
                self.display(auth, "RED")
        self.is_command = 0

    def cat(self):
        '''
        Functionality for cat command
        '''

        if self.curr_dir == "/root":
            self.display("Invalid command for root directory", "RED")
        else:
            fileserver_number = self.curr_dir.split("FS")[1]
            key = fileserver_keys[fileserver_number]
            f = Fernet(key)
            fileserver = ServerProxy(fileserver_addresses[fileserver_number])
            list_of_files = fileserver.get_files(node_number)
            files = []
            if not list_of_files:
                self.display("No files in the directory", "RED", True)
            else:
                for i in list_of_files:
                    file = (f.decrypt(i.data)).decode()
                    files.append(file)
                    self.display(file, "BLUE", True)
                self.display("Enter the file to display", "ORANGE")
                filename = self.wait_for_input(str)
                if filename not in files:
                    self.display("Invalid File", "RED")
                else:
                    text = fileserver.get_file_content(node_number, f.encrypt(str.encode(filename)))
                    if not text:
                        self.display("Server Error", "RED")
                    for i in text:
                        line = (f.decrypt(i.data)).decode()
                        self.display(line.strip(), "BLUE", True)
        self.is_command = 0

    def cp(self):
        '''
        Functionality for cp command
        '''

        if self.curr_dir == "/root":
            self.display("Invalid command for root directory", "RED")
        else:
            fileserver_number = self.curr_dir.split("FS")[1]
            key = fileserver_keys[fileserver_number]
            f = Fernet(key)
            fileserver = ServerProxy(fileserver_addresses[fileserver_number])
            list_of_files = fileserver.get_files(node_number)
            files = []
            if len(list_of_files)<2:
                self.display("Less than 2 files in the directory", "RED", True)
            else:
                for i in list_of_files:
                    file = (f.decrypt(i.data)).decode()
                    files.append(file)
                    self.display(file, "BLUE", True)
                self.display("Enter file 1 to be concatenated", "ORANGE")
                filename1 = self.wait_for_input(str)
                self.display("Enter file 2 to concatenate to file 1", "ORANGE")
                filename2 = self.wait_for_input(str)
                if not ((filename1 in files) and (filename2 in files)):
                    self.display("Invalid File entered", "RED")
                else:
                    success = fileserver.concatenate(
                        node_number,
                        f.encrypt(str.encode(filename1)),    
                        f.encrypt(str.encode(filename2))
                    )
                    if success:
                        self.display("Files successfully concatenated", "BLUE", True)
                    else:
                        self.display("Operation failed, try again.", "RED", True)
        self.is_command = 0

    def pwd(self):
        '''
        Functionality for pwd command
        '''
        
        self.display(" ")
        self.display(self.curr_dir, "BLUE")
        self.is_command = 0

    def ls(self):
        '''
        Functionality for ls command
        '''
        
        if self.curr_dir == "/root":
            if not self.is_logged_in:
                self.display("Login/Signup first", "RED", True)
                self.is_command = 0
                return
            else:
                self.curr_files = kdc.get_ls()
        else:
            fileserver_number = self.curr_dir.split("FS")[1]
            key = fileserver_keys[fileserver_number]
            f = Fernet(key)
            fileserver = ServerProxy(fileserver_addresses[fileserver_number])
            self.curr_files = fileserver.get_files(node_number)
        if not self.curr_files:
            self.display("No directories found.", "RED")
        else:
            for i in self.curr_files:
                try:
                    file = (f.decrypt(i.data)).decode()
                    self.display(file, "BLUE", True)
                except Exception:
                    self.display(i, "BLUE", True)
        self.is_command = 0
    
    def login(self):
        '''
        Functionality for login command
        '''
        
        if self.is_logged_in:
            self.display("Already logged in", "RED", True)
            self.is_command = 0
            return

        self.display("Enter Username: ")
        username = self.wait_for_input(str)
        self.display("Enter Password: ")
        password = self.wait_for_input(str)
        success = kdc.login(
            node_number,
            encrypt_message(server_key, str.encode(username)),
            encrypt_message(server_key, str.encode(password))
        )
        if success=="1":
            self.display("Logged in.", True)
            self.username = username
            self.is_logged_in = 1
        else:
            self.display(success, "RED", True)
        self.is_command = 0
    
    def logout(self):
        '''
        Functionality for logout command
        '''
        
        if self.is_logged_in:
            kdc.logout(encrypt_message(server_key, str.encode(self.username)))
            self.is_logged_in = 0
        else:
            self.display("User isn't logged in", "RED", True)
        self.is_logged_in = 0
        self.is_command = 0

    def signup(self):
        '''
        Functionality for signup command
        '''
        
        if self.is_logged_in:
            self.display("Already logged in", "RED", True)
            self.is_command = 0
            return

        self.display("Enter Username: ")
        username = self.wait_for_input(str)
        self.display("Enter Password (min length = 5): ")
        password = self.wait_for_input(str)
        while len(password)<5:
            self.display("Password length should be atleast 5", "RED", True)
            password = self.wait_for_input(str)
        success = kdc.signup(
            node_number,
            encrypt_message(server_key, str.encode(username)),
            encrypt_message(server_key, str.encode(password))
        )
        if success == "1":
            self.display("Signed up, logged in.", True)
            self.username = username
            self.is_logged_in = 1
        else:
            self.display(success, "RED", True)
        self.is_command = 0
    
    def wait_for_input(self, typecase):
        '''
        Retrieves user input from dialog box
        '''
        
        if self.command_queue:
            try:
                x = self.command_queue[0]
                del self.command_queue[0]
                temp = typecase(x)
                self.display(str(temp), True)
                return temp
            except:
                self.display("Enter a valid " + str(typecase).split("'")[1], 'RED')
        time.sleep(1)
        return self.wait_for_input(typecase)

class FormUi:

    def __init__(self, frame, queue):
        self.frame = frame
        self.queue = queue
        
        self.message = tk.StringVar()
        ttk.Label(self.frame, text='Command:').grid(column=0, row=1, sticky=W)
        self.entry = tk.Entry(self.frame, textvariable=self.message, width=25)
        self.entry.grid(column=1, row=1, sticky=(W, E))

        self.button = ttk.Button(self.frame, text='Submit', command=self.submit_message)
        self.button.grid(column=1, row=2, sticky=W)

    def submit_message(self):
        self.queue.append(self.message.get())
        self.entry.delete(0, 'end')


class ThirdUi:

    def __init__(self, frame):
        self.frame = frame
        ttk.Label(self.frame, text='Node running at:').grid(column=0, row=1, sticky=W)
        ttk.Label(self.frame, text=f'IP: {my_addr[0]}, Port: {my_addr[1]}').grid(column=0, row=4, sticky=W)


class App:

    def __init__(self, root, title):
        self.root = root
        root.title(title)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        # Create the panes and frames
        vertical_pane = ttk.PanedWindow(self.root, orient=VERTICAL)
        vertical_pane.grid(row=0, column=0, sticky="nsew")
        third_frame = ttk.Labelframe(vertical_pane, text="FileServer Info")
        vertical_pane.add(third_frame, weight=1)
        horizontal_pane = ttk.PanedWindow(vertical_pane, orient=HORIZONTAL)
        horizontal_pane2 = ttk.PanedWindow(vertical_pane, orient=HORIZONTAL)
        vertical_pane.add(horizontal_pane)
        vertical_pane.add(horizontal_pane2)
        form_frame = ttk.Labelframe(horizontal_pane, text="Shell")
        form_frame.columnconfigure(1, weight=1)
        horizontal_pane.add(form_frame, weight=1)
        console_frame = ttk.Labelframe(horizontal_pane, text="Console")
        console_frame.columnconfigure(0, weight=1)
        console_frame.rowconfigure(0, weight=1)
        horizontal_pane.add(console_frame, weight=1)

        form_frame2 = ttk.Labelframe(horizontal_pane2, text="Server")
        form_frame2.columnconfigure(1, weight=1)
        horizontal_pane2.add(form_frame2, weight=1)
        server_frame = ttk.Labelframe(horizontal_pane2, text="Server_Console")
        server_frame.columnconfigure(0, weight=1)
        server_frame.rowconfigure(0, weight=1)
        horizontal_pane2.add(server_frame, weight=1)

        self.third = ThirdUi(third_frame)
        self.form = FormUi(form_frame, console_queue)
        self.console = ConsoleUi(console_frame, console_queue)
        self.server = ConsoleUi(server_frame, server_queue)
        self.server_form = FormUi(form_frame2, server_queue)
        self.root.protocol('WM_DELETE_WINDOW', self.quit)
        self.root.bind('<Control-q>', self.quit)
        signal.signal(signal.SIGINT, self.quit)

    def quit(self, *args):
        self.root.destroy()
        os._exit(1)


def main():
    root = tk.Tk()
    app = App(root, f'Distributed Node{node_number} Panel')
    app.root.mainloop()

def task1():
    with SimpleXMLRPCServer(temp_addr, logRequests=False) as server:
        server.register_introspection_functions()
        class Distributed_Node:
            def test_server(self, addr):
                server_queue.append(f"Request from {addr}")
                return 1
            def register_file(self, file, server):
                prints(f"{file} created on FileServer {server}")
                return 1
            def register_server(self, server):
                prints(f"FS{server} created.")
                return 1
        
        server.register_instance(Distributed_Node())
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            prints("Server Terminated.")
            os._exit(1)


console_queue = []
server_queue = []
fileserver_keys = {}
fileserver_addresses = {}
my_addr = start_server()
temp_addr = my_addr
printc(f"New Node running at {my_addr}")
prints(f"Listening for incoming messages at {temp_addr}")

serv_add = f'http://127.0.0.1:8000'
kdc = ServerProxy(serv_add)

success = kdc.test_server()
if not success:
    print("Connection to server wasn't established.\nExiting now.")
    os.exit(1)

t1 = threading.Thread(target=task1, name='t1') 
t1.start()

private_key = get_new_key()
public_key = private_key.public_key()
response = kdc.register_node(my_addr, temp_addr, convert_public_key_to_bytes(public_key))
node_number, key = response[0], response[1].data
server_key = convert_bytes_to_public_key(key)
temp = encrypt_message(server_key, b"test_encryption")

printc(f"[+] Distributed Node {node_number} running")
main()