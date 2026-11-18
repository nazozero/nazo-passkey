$ErrorActionPreference = 'Stop'

choco install nasm --version=3.2.0 --yes --no-progress
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$nasmDir = Join-Path $env:ProgramFiles 'NASM'
$nasmDir | Out-File -FilePath $env:GITHUB_PATH -Encoding utf8 -Append
& (Join-Path $nasmDir 'nasm.exe') -v
exit $LASTEXITCODE
