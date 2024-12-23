# AutoC2
 	
![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white)

Basic C2 (Command & Control) server with a web frontend. "Attack" feature automatically scans the network for servers using known default credentials and installs implants to connect back to the server. 

## Example

![Dashboard](examples/dashboard.png)

## Installation & Usage
Download the repo then run the following commands to install dependencies into a virtual environment (recommended)
```
# Set up virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
Edit the config `server.conf` and then run the app
```
# Run AutoC2
python3 app.py
```

## Disclaimer

This tool is intended for ethical cybersecurity practices only and should be used exclusively in environments where explicit authorization has been granted. The user is fully responsible for any actions performed with this tool.

## Credit

This tool was built under mentorship of SiWan Kim (khc0ksw) at 싸이버원 (CYBERONE) in South Korea in November 2024.
