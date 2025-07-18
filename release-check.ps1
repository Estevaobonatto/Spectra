# Script PowerShell para verificacao de release
# Equivalente ao 'make release-check' para Windows

Write-Host "Verificacao de Release - Spectra v1.0.0" -ForegroundColor Green
Write-Host ("=" * 50)

# Funcao para executar comando e verificar resultado
function Invoke-CheckCommand {
    param(
        [string]$Command,
        [string]$Description
    )
    
    Write-Host "Verificando $Description..." -ForegroundColor Yellow
    
    try {
        $output = Invoke-Expression $Command 2>&1
        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq $null) {
            Write-Host "OK $Description - SUCESSO" -ForegroundColor Green
            return $true
        } else {
            Write-Host "ERRO $Description - FALHOU (Exit Code: $LASTEXITCODE)" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "ERRO $Description - EXCECAO: $_" -ForegroundColor Red
        return $false
    }
}

# Array para rastrear resultados
$results = @()

# 1. Verificar se Python esta instalado
Write-Host "`n1. Verificando Python..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "python --version" "Python instalado"

# 2. Verificar se pip esta instalado
Write-Host "`n2. Verificando pip..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "pip --version" "pip instalado"

# 3. Instalar dependencias de desenvolvimento
Write-Host "`n3. Instalando dependencias..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "pip install pytest pytest-cov black isort flake8 bandit safety build twine" "Dependencias de desenvolvimento"

# 4. Verificar formatacao com black
Write-Host "`n4. Verificando formatacao..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "black --check spectra/" "Formatacao Black"

# 5. Verificar imports com isort
Write-Host "`n5. Verificando imports..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "isort --check-only spectra/" "Organizacao de imports"

# 6. Verificar linting com flake8
Write-Host "`n6. Verificando linting..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "flake8 spectra/ --count --statistics" "Linting flake8"

# 7. Verificar seguranca com bandit
Write-Host "`n7. Verificando seguranca..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "bandit -r spectra/" "Analise de seguranca"

# 8. Verificar dependencias com safety
Write-Host "`n8. Verificando vulnerabilidades..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "safety check" "Vulnerabilidades em dependencias"

# 9. Executar testes
Write-Host "`n9. Executando testes..." -ForegroundColor Cyan
$results += Invoke-CheckCommand "pytest tests/ -v" "Testes unitarios"

# 10. Construir pacote
Write-Host "`n10. Construindo pacote..." -ForegroundColor Cyan
# Limpar builds anteriores
if (Test-Path "dist") { 
    Remove-Item -Recurse -Force "dist" 
}
if (Test-Path "build") { 
    Remove-Item -Recurse -Force "build" 
}
$results += Invoke-CheckCommand "python -m build" "Build do pacote"

# Resumo final
Write-Host "`n$('=' * 50)"
Write-Host "RESUMO DA VERIFICACAO" -ForegroundColor Cyan
Write-Host "$('=' * 50)"

$passed = ($results | Where-Object { $_ -eq $true }).Count
$total = $results.Count

if ($passed -eq $total) {
    Write-Host "SUCESSO! Todas as verificacoes passaram ($passed/$total)" -ForegroundColor Green
    Write-Host "Pronto para release v1.0.0!" -ForegroundColor Green
    
    Write-Host "`nPROXIMOS PASSOS:" -ForegroundColor Yellow
    Write-Host "1. git add ."
    Write-Host "2. git commit -m 'feat: release v1.0.0 - first official release'"
    Write-Host "3. git tag -a v1.0.0 -m 'Release v1.0.0 - First Official Release'"
    Write-Host "4. git push origin main"
    Write-Host "5. git push origin v1.0.0"
    Write-Host "6. twine upload dist/*  # Para publicar no PyPI"
    
} else {
    Write-Host "FALHOU! $($total - $passed) verificacoes falharam ($passed/$total)" -ForegroundColor Red
    Write-Host "Corrija os problemas antes do release" -ForegroundColor Yellow
    exit 1
}

Write-Host "`nArquivos gerados em dist/:" -ForegroundColor Cyan
if (Test-Path "dist") {
    Get-ChildItem "dist" | ForEach-Object { 
        Write-Host "  - $($_.Name)"
    }
}