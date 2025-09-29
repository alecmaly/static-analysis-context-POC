# receive messages from this socket and print to screen, basic socket server in python. Simple, no threading, just recv and print

import socket

def main():
	host = '127.0.0.1'
	port = 9999

	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_socket.bind((host, port))
	server_socket.listen(5)
	print(f"Listening on {host}:{port}")

	while True:
		client_socket, addr = server_socket.accept()
		print(f"Accepted connection from {addr}")
		handle_client(client_socket)

def handle_client(client_socket):
	while True:
		data = client_socket.recv(1024)
		if not data:
			break
		print(f"Received: {data.decode('utf-8')}")
	client_socket.close()

if __name__ == "__main__":
	main()
