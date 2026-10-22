# Run from the toolkit repository root. Optional Git mirror for official Sysmon docs.
$ErrorActionPreference = 'Stop'
$repoRoot = $PSScriptRoot
$knowledge = if ($env:TOOLKIT_DOCS_DIR) { $env:TOOLKIT_DOCS_DIR } elseif ($env:SOC_DOCS_DIR) { $env:SOC_DOCS_DIR } else { Join-Path $repoRoot 'knowledge' }
$destination = Join-Path (Join-Path $knowledge 'sources') 'sysinternals'
New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
if (Test-Path (Join-Path $destination '.git')) {
    git -C $destination pull --ff-only
} elseif (Test-Path $destination) {
    throw "Directory exists but is not a Git mirror: $destination"
} else {
    git clone --depth 1 --branch main https://github.com/MicrosoftDocs/sysinternals.git $destination
}
if ($LASTEXITCODE -ne 0) { throw 'Git sync failed' }
python -c "from toolkit.official_docs import build_index; print(build_index())"
if ($LASTEXITCODE -ne 0) { throw 'Building documentation index failed' }
python -c "from toolkit.official_docs import search_docs; print(search_docs('Sysmon process creation', collection='sysinternals', limit=2))"
if ($LASTEXITCODE -ne 0) { throw 'Documentation search smoke test failed' }
