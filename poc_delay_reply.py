#!/usr/bin/env python3
import socket, time
HOST='127.0.0.1'
PORT=4321
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
s.bind((HOST,PORT)); s.listen(1)
conn,addr = s.accept()
print("connected; sleeping before sending reply")
time.sleep(30)   # client will block on recv() unless it has a timeout
conn.sendall(b"short reply")
conn.close(); s.close()
