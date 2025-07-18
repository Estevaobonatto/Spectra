# Script PowerShell para verificação de release
# Equivalente ao 'make release-check' para Windows

Write-Host "🚀 Verificação de Release - Spectra v1.0.0" -ForegroundColor Green
Write-Host "=" * 50

# Função para executar comando e verificar resultado
function Invoke-CheckCommand {
    param(
        [string]$Command,
        [string]$Description
    )
    
    Write-Host "🔍 $Description..." -ForegroundColor Yellow
    
    try {
        Invoke-Expression $Command
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ $Description - OK" -ForegroundColor Green
            return $true
        } else {
            Write-Host "❌ $Description - FALHOU" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "❌ $Description - ERRO: $_" -ForegroundColor Red
        return $false
    }
}

# Array para rastrear resultados
$results = @()

# 1. Verificar se Python está instalado
Write-Host "`n📋 1. Verificando Python..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "python --version" "Python instalado"

# 2. Verificar se pip está instalado
Write-Host "`n📋 2. Verificando pip..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "pip --version" "pip instalado"

# 3. Instalar dependências de desenvolvimento
Write-Host "`n📋 3. Instalando dependências..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "pip install pytest pytest-cov black isort flake8 bandit safety build twine" "Dependências de desenvolvimento"

# 4. Verificar formatação com black
Write-Host "`n📋 4. Verificando formatação..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "black --check spectra/" "Formatação Black"

# 5. Verificar imports com isort
Write-Host "`n📋 5. Verificando imports..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "isort --check-only spectra/" "Organização de imports"

# 6. Verificar linting com flake8
Write-Host "`n📋 6. Verificando linting..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "flake8 spectra/ --count --statistics" "Linting flake8"

# 7. Verificar segurança com bandit
Write-Host "`n📋 7. Verificando segurança..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "bandit -r spectra/" "Análise de segurança"

# 8. Verificar dependências com safety
Write-Host "`n📋 8. Verificando vulnerabilidades..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "safety check" "Vulnerabilidades em dependências"

# 9. Executar testes
Write-Host "`n📋 9. Executando testes..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "pytest tests/ -v" "Testes unitários"

# 10. Construir pacote
Write-Host "`n📋 10. Construindo pacote..." -ForegroundColor Cyan
# Limpar builds anteriores
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
$results += Invoke-CheckCommand "python -m build" "Build do pacote"

# Resumo final
Write-Host "`n" + "=" * 50
Write-Host "📊 RESUMO DA VERIFICAÇÃO" -ForegroundColor Cyan
Write-Host "=" * 50

$passed = ($results | Where-Object { $_ -eq $true }).Count
$total = $results.Count

if ($passed -eq $total) {
    Write-Host "🎉 SUCESSO! Todas as verificações passaram ($passed/$total)" -ForegroundColor Green
    Write-Host "✅ Pronto para release v1.0.0!" -ForegroundColor Green
    
    Write-Host "`n🚀 PRÓXIMOS PASSOS:" -ForegroundColor Yellow
    Write-Host "1. git add ."
    Write-Host "2. git commit -m 'feat: release v1.0.0 - first official release'"
    Write-Host "3. git tag -a v1.0.0 -m 'Release v1.0.0 - First Official Release'"
    Write-Host "4. git push origin main"
    Write-Host "5. git push origin v1.0.0"
    Write-Host "6. twine upload dist/*  # Para publicar no PyPI"
    
} else {
    Write-Host "❌ FALHOU! $($total - $passed) verificações falharam ($passed/$total)" -ForegroundColor Red
    Write-Host "🔧 Corrija os problemas antes do release" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n📦 Arquivos gerados em dist/:" -ForegroundColor Cyan
if (Test-Path "dist") {
    Get-ChildItem "dist" | ForEach-Object { Write-Host "  - $($_.Name)" }
}