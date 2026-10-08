[CmdletBinding()]
param(
    [string]$Version = '0.4.4',
    [string]$X64 = '',
    [string]$X86 = '',
    [string]$Output = '',
    [Parameter(Mandatory = $true)][string]$ExpectedX64Sha256,
    [Parameter(Mandatory = $true)][string]$ExpectedX86Sha256
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'Version deve usar N.N.N.' }
if (-not $X64) { $X64 = Join-Path $projectRoot "artifacts\server-upload-$Version\windows-firaw-ssh-x64.exe" }
if (-not $X86) { $X86 = Join-Path $projectRoot "artifacts\server-upload-$Version\windows-firaw-ssh-x86.exe" }
if (-not $Output) { $Output = Join-Path $projectRoot "artifacts\server-upload-$Version\Firaw-SSH-Universal-$Version.exe" }
$expectedSigner = '9A2EFF2483185C9A900F2797D7A9CBD5E8A12893'
$expectedHashes = @{
    x64 = $ExpectedX64Sha256.ToUpperInvariant()
    x86 = $ExpectedX86Sha256.ToUpperInvariant()
}
if ($expectedHashes.x64 -notmatch '^[0-9A-F]{64}$' -or $expectedHashes.x86 -notmatch '^[0-9A-F]{64}$') {
    throw 'Informe os dois SHA-256 completos dos pacotes assinados.'
}
$packageVersion = (Get-Content -LiteralPath (Join-Path $projectRoot 'package.json') -Raw | ConvertFrom-Json).version
$tauriVersion = (Get-Content -LiteralPath (Join-Path $projectRoot 'src-tauri\tauri.conf.json') -Raw | ConvertFrom-Json).version
if ($packageVersion -ne $Version -or $tauriVersion -ne $Version) {
    throw "Versoes de package.json e tauri.conf.json devem ser $Version."
}

foreach ($item in @(@{ Arch = 'x64'; Path = $X64 }, @{ Arch = 'x86'; Path = $X86 })) {
    if (-not (Test-Path -LiteralPath $item.Path -PathType Leaf)) { throw "Pacote $($item.Arch) nao encontrado." }
    $hash = (Get-FileHash -LiteralPath $item.Path -Algorithm SHA256).Hash
    $signature = Get-AuthenticodeSignature -LiteralPath $item.Path
    $packageProductVersion = (Get-Item -LiteralPath $item.Path).VersionInfo.ProductVersion
    if ($hash -ne $expectedHashes[$item.Arch] -or $signature.Status -ne 'Valid' -or
        $signature.SignerCertificate.Thumbprint -ne $expectedSigner -or -not $signature.TimeStamperCertificate -or
        $packageProductVersion -ne $Version) {
        throw "Pacote $($item.Arch) nao passou em versao, SHA-256, assinatura ou carimbo de tempo."
    }
}

$makensis = Join-Path $env:LOCALAPPDATA 'tauri\NSIS\makensis.exe'
$signtool = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
$script = Join-Path $PSScriptRoot '..\packaging\windows\UniversalInstaller.nsi'
foreach ($required in @($makensis, $signtool, $script)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Dependencia nao encontrada: $required" }
}
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$expectedSigner"
if (-not $certificate.HasPrivateKey -or $certificate.NotAfter -le (Get-Date)) {
    throw 'Certificado de assinatura indisponivel ou vencido.'
}

$outputDir = Split-Path -Parent $Output
$null = New-Item -ItemType Directory -Path $outputDir -Force
& $makensis '/V2' "/DX64FILE=$X64" "/DX86FILE=$X86" "/DOUTPUTFILE=$Output" "/DVERSION=$Version" $script
if ($LASTEXITCODE -ne 0) { throw "Compilacao NSIS falhou ($LASTEXITCODE)." }
& $signtool sign /sha1 $expectedSigner /fd sha256 /tr 'http://timestamp.digicert.com' /td sha256 $Output
if ($LASTEXITCODE -ne 0) { throw "Assinatura falhou ($LASTEXITCODE)." }
$signature = Get-AuthenticodeSignature -LiteralPath $Output
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $expectedSigner -or
    -not $signature.TimeStamperCertificate) { throw 'Assinatura final invalida.' }

[pscustomobject]@{
    File = $Output
    Bytes = (Get-Item -LiteralPath $Output).Length
    Sha256 = (Get-FileHash -LiteralPath $Output -Algorithm SHA256).Hash
    Signer = $signature.SignerCertificate.Thumbprint
    Timestamped = [bool]$signature.TimeStamperCertificate
}
