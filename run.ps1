$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$PythonBin = if ($env:PYTHON_BIN) { $env:PYTHON_BIN } else { "python" }
$VenvDir = if ($env:TOXICJOIN_VENV) { $env:TOXICJOIN_VENV } else { ".venv" }
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$Launcher = Join-Path $VenvDir "Scripts\toxicjoin-api.exe"

if (-not (Get-Command $PythonBin -ErrorAction SilentlyContinue)) {
    throw "Python 3.11 or 3.12 is required."
}

if (-not (Test-Path $VenvPython)) {
    & $PythonBin -m venv $VenvDir
}

& $VenvPython -m pip install --upgrade pip
& $VenvPython -m pip install -e .
& $Launcher
