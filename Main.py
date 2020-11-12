from helper_functions import *    
import os
from sys import platform

def main():
    pwd = get_parent_path(__file__)
    n = int(input("Enter number of servers to be created : "))
    server_count = 0
    dest = os.path.join(pwd, "FileServer_init.py")
    command = command = "python3 " + dest
    if platform=="windows":
        command = "start /wait cmd /c C:/Python37/python.exe " + dest
    while server_count < n:
        os.system(command)
        server_count += 1


remove_servers()
main()