import os
import sys
import json
import subprocess
from pathlib import Path

def update_log(key, count):
    with open(filename, 'r') as f:
        data = json.load(f)
        data[key] = count

    os.remove(filename)
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

pwd = Path(__file__).parent.absolute()
filename = os.path.join(pwd, "log.json")
with open(filename, 'r') as f:
    data = json.load(f)
    port = data["port"]
    key = data["key"]
if not port:
    port = int(sys.argv[1])
    update_log("port", port)

path = os.path.join(pwd, "GUI.pyw")
if sys.platform == "linux":
    subprocess.Popen(['python3', path])
else:
    os.startfile(path)
exit()
