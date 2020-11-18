import os
import sys
import json
import subprocess
from pathlib import Path


pwd = Path(__file__).parent.absolute()
path = os.path.join(pwd, "DiS.py")
print(path)
n = int(input("Enter number of nodes: "))
if sys.platform == "linux":
    for i in range(n):
        subprocess.Popen(['python3', path])
else:
    for i in range(n):
        os.startfile(path)
exit()
