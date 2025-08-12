#!/usr/bin/env python3
import socket, time

HOST='127.0.0.1'
PORT=4321

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(1)
print("SIGPIPE POC server listening on", PORT)
conn, addr = s.accept()
print("client connected, closing immediately")
conn.close()
s.close()
time.sleep(0.5)
print("done")
