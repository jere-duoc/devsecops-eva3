# Crea un entorno virtual de Python con Flask y levanta la app en http://localhost:8000
# Uso (PowerShell, dentro de securedev-lab):
#   powershell -ExecutionPolicy Bypass -File .\crear-entorno.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv")) {
    Write-Host "Creando entorno virtual .venv ..."
    python -m venv .venv
}

Write-Host "Instalando dependencias (Flask, Werkzeug, prometheus-client) ..."
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# Clave de sesión aleatoria en cada ejecución (nunca fija en el código)
$env:SECRET_KEY    = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
$env:DATABASE_PATH = Join-Path $PSScriptRoot "securedev.db"

Write-Host "Levantando app en http://localhost:8000  (Ctrl+C para detener)"
.\.venv\Scripts\python.exe app.py
