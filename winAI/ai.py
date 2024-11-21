import socket
import nmap

class Host:
    def __init__(self, host, vuln):
        self.host = host
        self.vuln = vuln
        self.ports = []

    def __str__(self):
        ports_str = ", ".join(map(str, self.ports)) if self.ports else "None"
        return f"{self.host} ({self.os})\nports: {ports_str}\nvuln: {self.vuln}"

def preprocess():
    hosts = []
    with open("train.csv", 'r') as file:
        for line in file:
            split_line = line.split(',')
            host = split_line[0]
            vuln = split_line[1]
            new_host = Host(host, vuln)
            for p in split_line[2:]:
                new_host.ports.append(int(p.strip()))
            hosts.append(new_host)
    print("----------------------------------------")
    for host in hosts:
        print(host)
        print("----------------------------------------")

def scan(subnet="192.168.108.0/24", ports="21,80,88,389,445,3389"):
    # Initialize the Nmap PortScanner
    nm = nmap.PortScanner()

    print(f"Scanning subnet {subnet} for ports {ports}...")

    # Perform the scan
    nm.scan(hosts=subnet, ports=ports, arguments="")

    # Process and report the results
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            open_ports = [port for port in nm[host].all_tcp() if nm[host]["tcp"][port]["state"] == "open"]
            if open_ports:
                print(f"Host: {host}")
                print(f"  Open Ports: {','.join(map(str, open_ports))}")

if __name__=="__main__":
    scan()
