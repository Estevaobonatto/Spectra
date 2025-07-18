# Script para publicar no PyPI
# Execute após criar conta e token no PyPI

Write-Host "📦 Publicando Spectra no PyPI..." -ForegroundColor Green

# Verificar se twine está instalado
try {
    twine --version | Out-Null
} catch {
    Write-Host "❌ Twine não encontrado. Instalando..." -ForegroundColor Red
    pip install twine
}

# Verificar arquivos
Write-Host "🔍 Verificando arquivos de distribuição..." -ForegroundColor Yellow
if (-not (Test-Path "dist")) {
    Write-Host "❌ Pasta dist/ não encontrada. Execute primeiro: python -m build" -ForegroundColor Red
    exit 1
}

$files = Get-ChildItem "dist" -Filter "spectra_suite-1.0.0*"
if ($files.Count -eq 0) {
    Write-Host "❌ Arquivos de distribuição não encontrados em dist/" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Arquivos encontrados:" -ForegroundColor Green
$files | ForEach-Object { Write-Host "  - $($_.Name)" }

# Verificar integridade
Write-Host "`n🔍 Verificando integridade dos arquivos..." -ForegroundColor Yellow
twine check dist/spectra_suite-1.0.0*

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Verificação de integridade falhou!" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Verificação de integridade passou!" -ForegroundColor Green

# Upload
Write-Host "`n🚀 Fazendo upload para PyPI..." -ForegroundColor Yellow
Write-Host "💡 Use '__token__' como username e seu token de API como password" -ForegroundColor Cyan

twine upload dist/spectra_suite-1.0.0*

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n🎉 Publicação no PyPI concluída com sucesso!" -ForegroundColor Green
    Write-Host "📦 Spectra agora pode ser instalado com: pip install spectra-suite" -ForegroundColor Cyan
    Write-Host "🔗 Verifique em: https://pypi.org/project/spectra-suite/" -ForegroundColor Cyan
} else {
    Write-Host "`n❌ Falha na publicação. Verifique suas credenciais." -ForegroundColor Red
}