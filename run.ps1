$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RootDir

$PythonBin = if ($env:PYTHON_BIN) { $env:PYTHON_BIN } else { "python" }
$DiagnosticsDir = if ($env:TOXICJOIN_BOOTSTRAP_DIAGNOSTICS_DIR) {
    $env:TOXICJOIN_BOOTSTRAP_DIAGNOSTICS_DIR
} else {
    ".toxicjoin\bootstrap"
}
$env:UV_PROJECT_ENVIRONMENT = if ($env:TOXICJOIN_VENV) { $env:TOXICJOIN_VENV } else { ".venv" }
New-Item -ItemType Directory -Force -Path $DiagnosticsDir | Out-Null

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE: $Command $($Arguments -join ' ')"
    }
}

if (-not (Get-Command $PythonBin -ErrorAction SilentlyContinue)) {
    throw "An exact platform-supported Python from config/toolchain.json is required."
}

Invoke-Checked $PythonBin scripts/bootstrap.py verify `
    --components python,locks,contract `
    --output (Join-Path $DiagnosticsDir "pre-uv.json")

$Contract = Get-Content -Raw -Encoding UTF8 "config/toolchain.json" | ConvertFrom-Json
$UvVersion = $Contract.uv.version
$UvCandidate = if ($env:TOXICJOIN_UV_BIN) { $env:TOXICJOIN_UV_BIN } else { "uv" }
$UvCommand = Get-Command $UvCandidate -ErrorAction SilentlyContinue

if ($UvCommand) {
    $UvBin = $UvCommand.Source
} else {
    Invoke-Checked $PythonBin -m pip install --disable-pip-version-check "uv==$UvVersion"
    $ScriptsDir = & $PythonBin -c "import sysconfig; print(sysconfig.get_path('scripts'))"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not resolve the Python scripts directory."
    }
    $UvBin = Join-Path $ScriptsDir "uv.exe"
}

if (-not (Test-Path $UvBin)) {
    throw "Exact uv executable was not found at $UvBin"
}

$env:TOXICJOIN_UV_BIN = $UvBin
Invoke-Checked $PythonBin scripts/bootstrap.py verify `
    --components python,uv,locks,contract `
    --output (Join-Path $DiagnosticsDir "toolchain.json")
Invoke-Checked $PythonBin scripts/bootstrap.py sync `
    --output (Join-Path $DiagnosticsDir "sync.json")

& $UvBin run --frozen toxicjoin-api
exit $LASTEXITCODE
