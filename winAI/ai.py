import socket
import nmap
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np

class Host:
    def __init__(self, host, vuln):
        self.host = host
        self.vuln = vuln
        self.ports = []
        self.ports_bin = [0, 0, 0, 0, 0, 0]  # 21, 80, 88, 389, 445, 3389

    def __str__(self):
        ports_str = ", ".join(map(str, self.ports)) if self.ports else "None"
        return f"{self.host} ({self.vuln})\nports: {ports_str}"

# Map ports to indices
port_map = {"21": 0, "80": 1, "88": 2, "389": 3, "445": 4, "3389": 5}

# Mapping vulnerability names to integers
vuln_map = {"none": 0, "eb": 1, "zl": 2, "bk": 3}

# Preprocess function for training or testing data
def preprocess(file_path):
    hosts = []
    labels = []
    X = []
    with open(file_path, 'r') as file:
        for line in file:
            split_line = line.split(',')
            host = split_line[0]
            vuln = split_line[1].strip()  # Vulnerability type as string
            vuln_label = vuln_map.get(vuln, 0)  # Map the vulnerability to its corresponding label, default to 'none'
            new_host = Host(host, vuln_label)
            
            for p in split_line[2:]:
                new_host.ports.append(int(p.strip()))
                new_host.ports_bin[port_map[p.strip()]] = 1
            
            hosts.append(new_host)
            X.append(new_host.ports_bin)
            labels.append(vuln_label)

    # Convert lists into numpy arrays
    X = np.array(X)
    labels = np.array(labels)
    
    return X, labels

# Neural Network model for multi-class classification
class VulnerabilityNN(nn.Module):
    def __init__(self):
        super(VulnerabilityNN, self).__init__()
        # Define the layers
        self.fc1 = nn.Linear(6, 8)  # 6 input features (ports_bin), 8 neurons in the first hidden layer
        self.fc2 = nn.Linear(8, 4)  # 8 neurons from previous layer, 4 neurons in this layer
        self.fc3 = nn.Linear(4, 4)  # 4 neurons in the second hidden layer, 4 output neurons (for 4 classes)
        self.softmax = nn.Softmax(dim=1)  # Softmax activation function for multi-class classification

    def forward(self, x):
        x = torch.relu(self.fc1(x))  # ReLU activation after first layer
        x = torch.relu(self.fc2(x))  # ReLU activation after second layer
        x = self.fc3(x)  # No activation after the final layer (Softmax is applied later)
        return x

# Convert data to torch tensors
def create_tensors(X, y):
    X_tensor = torch.tensor(X, dtype=torch.float32)
    y_tensor = torch.tensor(y, dtype=torch.long)  # Long type for multi-class classification
    return X_tensor, y_tensor

# Training function
def train(model, X_train, y_train, num_epochs=100, learning_rate=0.001):
    criterion = nn.CrossEntropyLoss()  # Cross-Entropy Loss for multi-class classification
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)

    for epoch in range(num_epochs):
        model.train()
        optimizer.zero_grad()
        
        outputs = model(X_train)  # Forward pass
        loss = criterion(outputs, y_train)  # Calculate loss
        loss.backward()  # Backpropagation
        optimizer.step()  # Update weights
        
        if epoch % 10 == 0:
            print(f'Epoch {epoch}/{num_epochs}, Loss: {loss.item()}')

# Evaluation function
def evaluate(model, X_test, y_test):
    model.eval()
    with torch.no_grad():
        outputs = model(X_test)
        _, predictions = torch.max(outputs, 1)  # Get the class with the highest probability
        accuracy = (predictions == y_test).float().mean()
        print(f'Accuracy: {accuracy.item() * 100}%')

# Main execution
if __name__ == "__main__":
    # Load and preprocess the training data
    X_train, y_train = preprocess("train.txt")
    X_train_tensor, y_train_tensor = create_tensors(X_train, y_train)

    # Load and preprocess the test data
    X_test, y_test = preprocess("test.txt")
    X_test_tensor, y_test_tensor = create_tensors(X_test, y_test)

    # Initialize the model
    model = VulnerabilityNN()

    # Train the model
    train(model, X_train_tensor, y_train_tensor, num_epochs=100, learning_rate=0.001)

    # Evaluate the model
    evaluate(model, X_test_tensor, y_test_tensor)

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
