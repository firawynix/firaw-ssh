param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$File
)

$ErrorActionPreference = "Stop"

$thumbprint = $env:FIRAW_SIGNING_THUMBPRINT
if ([string]::IsNullOrWhiteSpace($thumbprint)) {
    Write-Host "FIRAW_SIGNING_THUMBPRINT ausente; mantendo artefato sem assinatura."
    exit 0
}

$signTool = $env:FIRAW_SIGNTOOL
if ([string]::IsNullOrWhiteSpace($signTool) -or -not (Test-Path -LiteralPath $signTool)) {
    throw "FIRAW_SIGNTOOL nao aponta para um signtool.exe valido."
}

& $signTool sign /fd SHA256 /sha1 $thumbprint /tr http://timestamp.digicert.com /td SHA256 $File
if ($LASTEXITCODE -ne 0) {
    throw "Falha ao assinar $File"
}
