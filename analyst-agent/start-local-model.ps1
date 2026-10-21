# Starts local Qwen with a single inference slot (full configured context).
# Change -ModelPath / -ServerPath when your installation lives elsewhere.
[CmdletBinding()]
param(
    [string]$ServerPath = 'C:\Agents\llama_cpp\llama-server.exe',
    [string]$ModelPath = 'C:\Agents\models\Qwen_Qwen3.5-9B-Q4_K_M.gguf',
    [ValidateRange(4096,131072)][int]$ContextTokens = 32768,
    [ValidateRange(1,65535)][int]$Port = 8081,
    [ValidateRange(0,999)][int]$GpuLayers = 99
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $ServerPath)) { throw "Missing llama-server.exe: $ServerPath" }
if (-not (Test-Path $ModelPath)) { throw "Missing model file: $ModelPath" }
Write-Host "Starting llama.cpp (port=$Port, context=$ContextTokens, parallel=1, gpu layers=$GpuLayers)"
Write-Host 'If the server exits due to memory pressure, use -ContextTokens 16384 and set LLM_CONTEXT_TOKENS=16384 in .env.'
& $ServerPath -m $ModelPath --host 127.0.0.1 --port $Port --jinja -c $ContextTokens -np 1 -ngl $GpuLayers
if ($LASTEXITCODE -ne 0) { throw "llama-server exited with code $LASTEXITCODE" }
