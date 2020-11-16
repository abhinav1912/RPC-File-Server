import os
import sys
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.client import ServerProxy
from cryptography.fernet import Fernet
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
from random import randint

def get_parent_path():
    return Path(__file__).parent.absolute()

def prints(msg):
    server_queue.append(msg)

def printc(msg):
    console_queue.append(msg)

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

# server_number = (str(pwd).split("/")[-1]).split("FS")[-1]
pwd = get_parent_path()
filename = os.path.join(pwd, "log.json")
with open(filename, 'r') as f:
    data = json.load(f)
    addr, port = data["kdcIP"], data["kdcPort"]

serv_add = f'http://{addr}:{port}'
kdc = ServerProxy(serv_add)


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
        server_key = convert_bytes_to_public_key(str.encode(data["server_key"]))
    if not port:
        port = int(sys.argv[1])
        key = sys.argv[2]
        update_log("port", port)
        update_log("key", key)
    self_addr = ('', port)
    return self_addr, str.encode(key)


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
        self.scrolled_text.tag_config('CRITICAL', foreground='red', underline=1)
        self.command_list = ["touch", "cd", "ls", "cat", "pwd", "cp"]
        self.command_queue = []
        self.is_command = 0
        self.frame.after(100, self.poll_log_queue)

    def display(self, record, style = 'INFO'):
        self.scrolled_text.configure(state='normal')
        self.scrolled_text.insert(tk.END, ">>> " + str(record) + '\n', style)
        self.scrolled_text.configure(state='disabled')
        self.scrolled_text.yview(tk.END)
        if record == "Register File":
            pass

    def poll_log_queue(self):
        while True:
            if not self.queue:
                break
            else:
                record = self.queue[0]
                del self.queue[0]
                # self.display(record) 
                if record.lower() in self.command_list and not self.is_command:
                    self.is_command = 1
                    if record.lower() == "touch":
                        self.display(record)
                        temp_thread = threading.Thread(target=self.create_files)
                        temp_thread.start()
                elif self.is_command:
                    self.command_queue.append(record)
                else:
                    self.display(record)
        self.frame.after(500, self.poll_log_queue)
    
    def create_files(self):
        self.display("Enter number of files to create: ")
        n = self.wait_for_input(int)
        self.display(n)
        # self.display("User entered "+str(n))
        for i in range(n):
            self.display(f"Creating new file")
            self.display("Do you want to add text (0/1): ")
            x = self.wait_for_input(int)
            text = ""
            if x:
                self.display("Enter text: ", 'ORANGE')
                text = self.wait_for_input(str)
                self.display("Entered text: "+text)
            try:
                file_count = kdc.register_file(server_number)
                new_file = os.path.join(pwd, f"file{file_count}.txt")
                with open(new_file, 'w') as file:
                    if text:
                        file.write(text)
                update_log("files", file_count)
                self.display(f"file{file_count}.txt successfully created.", 'BLUE')
            except Exception:
                self.display("Server Error, file not created.", "RED")
        self.is_command = 0
        return
    
    def wait_for_input(self, typecase):
        if self.command_queue:
            try:
                x = self.command_queue[0]
                del self.command_queue[0]
                temp = typecase(x)
                # print (x, temp)
                return temp
            except:
                self.display("Enter a valid " + str(typecase).split("'")[1], 'RED')
        time.sleep(1)
        return self.wait_for_input(typecase)

class FormUi:

    def __init__(self, frame, queue):
        self.frame = frame
        self.queue = queue
        # Create a combobbox to select the logging level
        values = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        self.level = tk.StringVar()
        ttk.Label(self.frame, text='Level:').grid(column=0, row=0, sticky=W)
        self.combobox = ttk.Combobox(
            self.frame,
            textvariable=self.level,
            width=25,
            state='readonly',
            values=values
        )
        self.combobox.current(0)
        self.combobox.grid(column=1, row=0, sticky=(W, E))
        # Create a text field to enter a message
        self.message = tk.StringVar()
        ttk.Label(self.frame, text='Message:').grid(column=0, row=1, sticky=W)
        self.entry = tk.Entry(self.frame, textvariable=self.message, width=25)
        self.entry.grid(column=1, row=1, sticky=(W, E))
        # Add a button to log the message
        self.button = ttk.Button(self.frame, text='Submit', command=self.submit_message)
        self.button.grid(column=1, row=2, sticky=W)

    def submit_message(self):
        # Get the logging level numeric value
        self.queue.append(self.message.get())
        self.entry.delete(0, 'end')


class ThirdUi:

    def __init__(self, frame):
        self.frame = frame
        ttk.Label(self.frame, text='Server running at:').grid(column=0, row=1, sticky=W)
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
        # self.clock.stop()
        self.root.destroy()
        os._exit(1)


def main():
    # logging.basicConfig(level=logging.DEBUG)
    root = tk.Tk()
    app = App(root, f'FileServer{server_number} Panel')
    app.root.mainloop()

def task1():
    with SimpleXMLRPCServer(my_addr, logRequests=False) as server:
        server.register_introspection_functions()
        class File_Server():
            def test_server(self, addr):
                server_queue.append(f"Request from {addr}")
                return server_number
            
            def is_node_authenticated(self, node):
                node = decrypt_message(private_key, node.data).decode()
                return str(str(node) in authenticated)

            def authenticate(self, node, temp_key):
                sess_key = decrypt_message(private_key, temp_key.data)
                f = Fernet(sess_key)
                nonce = randint(10**5, 10**6)
                sess_keys[node] = sess_key
                nonces[node] = nonce
                authenticated.append(str(node))
                return f.encrypt(str.encode(str(nonce)))
            
            def confirm_auth(self, node, nonce):
                if node not in sess_keys.keys() or node not in nonces.keys():
                    return 0
                nonce = nonce.data
                sess_key = sess_keys[node]
                f = Fernet(sess_key)
                nonce = int((f.decrypt(nonce)).decode())
                if nonces[node]-nonce == 1:
                    return 1
                return 0
            
            def get_files(self):
                pwd = get_parent_path()
                files = os.listdir(pwd)
                output = []
                for i in files:
                    if ".txt" in i:
                        output.append(i)
                return output

        server.register_instance(File_Server())
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            prints("Server Terminated.")
            os._exit(1)

console_queue = []
server_queue = []
authenticated = []
sess_keys = {}
nonces = {}
my_addr, key = start_server()
private_key = convert_bytes_to_private_key(key)
public_key = private_key.public_key()
server_number = str(pwd).split("/FS")[-1]
t1 = threading.Thread(target=task1, name='t1') 
t1.start()
if not my_addr[0]:
    my_addr = ('127.0.0.1', my_addr[1])
main()
prints(f"[+] Fileserver {server_number} running")
success = kdc.test_server()
if not success:
    prints("Connection to server wasn't established.\nExiting now.")
    os.exit(1)
# create_files()
