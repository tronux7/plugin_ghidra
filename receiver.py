import socket
import threading
import hashlib

s = socket.socket()
host = socket.gethostname()
port = 8080
s.bind((host,port))
filename = ""
s.listen(10)
file_dest_path =  #YOUR DESTINATION PATH HERE
conn,addr = s.accept()

print ("[+] Waiting for a connection")
while True:
    print("[+] Got a connection from %s" % str(addr))
    
    size = conn.recv(16).decode()
    if not size:
        break
    size = int(size, 2)
    filename = conn.recv(size).decode()
    filesize = conn.recv(32).decode()
    filesize = int(filesize, 2)
    file_to_write = open(file_dest_path+filename, 'wb')
    chunksize = 4096
    while filesize > 0:
        if filesize < chunksize:
            chunksize = filesize
        data = conn.recv(chunksize)
        file_to_write.write(data)
        filesize -= len(data)

    file_to_write.close()
    print ("[+] File received successfully")
s.close()
