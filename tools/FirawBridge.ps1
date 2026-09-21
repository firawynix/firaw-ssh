param(
    [ValidateSet('ping', 'list', 'exec', 'download', 'upload')]
    [string]$Action = 'list',
    [string]$ProfileId,
    [string]$Command,
    [string[]]$RemotePaths,
    [string[]]$LocalPaths,
    [string]$RemoteDirectory,
    [string]$LocalDirectory
)

$request = @{ action = $Action }
if ($ProfileId) { $request.profileId = $ProfileId }
if ($Command) { $request.command = $Command }
if ($RemotePaths) { $request.remotePaths = $RemotePaths }
if ($LocalPaths) { $request.localPaths = $LocalPaths }
if ($RemoteDirectory) { $request.remoteDirectory = $RemoteDirectory }
if ($LocalDirectory) { $request.localDirectory = $LocalDirectory }

$pipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', 'firaw-ssh-bridge-v1.sock', [System.IO.Pipes.PipeDirection]::InOut)
try {
    $pipe.Connect(3000)
    $writer = [System.IO.StreamWriter]::new($pipe, [System.Text.UTF8Encoding]::new($false), 4096, $true)
    $reader = [System.IO.StreamReader]::new($pipe, [System.Text.UTF8Encoding]::new($false), $false, 4096, $true)
    $writer.AutoFlush = $true
    $writer.WriteLine(($request | ConvertTo-Json -Compress -Depth 8))
    $response = $reader.ReadLine()
    if (-not $response) { throw 'A ponte encerrou sem responder.' }
    $response | ConvertFrom-Json
} finally {
    if ($reader) { $reader.Dispose() }
    if ($writer) { $writer.Dispose() }
    $pipe.Dispose()
}
