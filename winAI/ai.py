
class Host:
    def __init__(self, hostname, os, vuln):
        self.hostname = hostname
        self.os = os
        self.vuln = vuln
        self.ports = []

    def __str__(self):
        ports_str = ", ".join(map(str, self.ports)) if self.ports else "None"
        return f"{self.hostname} ({self.os})\nports: {ports_str}\nvuln: {self.vuln}"

def preprocess():
    hosts = []
    with open("train.csv", 'r') as file:
        for line in file:
            split_line = line.split(',')
            hostname = split_line[0]
            os = split_line[1]
            vuln = split_line[2]
            new_host = Host(hostname, os, vuln)
            for p in split_line[3:]:
                new_host.ports.append(int(p.strip()))
            hosts.append(new_host)
    print("----------------------------------------")
    for host in hosts:
        print(host)
        print("----------------------------------------")

if __name__=="__main__":
    preprocess()
