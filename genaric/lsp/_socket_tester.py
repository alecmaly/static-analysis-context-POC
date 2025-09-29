import socket
import sys

if len(sys.argv) < 2:
    print("Usage: python _socket_tester.py /path/to/file.ext")
    sys.exit(1)

file_path = sys.argv[1]

HOST = '127.0.0.1'
PORT = 9999

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(file_path.encode() + b"\n")
    print(f"[Client] Sent file path: {file_path}")
