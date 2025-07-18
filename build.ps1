# Script PowerShell para build rápido
# Para Windows - equivalente aos comandos make

param(
    [string]$Action = "help"
)

function Show-Help {
    Write-Host "🔧 Scripts de Build - Spectra v1.0.0" -ForegroundColor Green
    Write-Host "Uso: .\build.ps1 <ação>"
    Write-Host ""
    Write-Host "Ações disponíveis:" -ForegroundColor Yellow
    Write-Host "  help          - Mostra esta ajuda"
    Write-Host "  install       - Instala dependências"
    Write-Host "  test          - Executa testes"
    Write-Host "  format        - Formata código"
    Write-Host "  lint          - Verifica linting"
    Write-Host "  security      - Verifica segurança"
    Write-Host "  build         - Constrói pacote"
    Write-Host "  clean         - Limpa arquivos temporários"
    Write-Host "  release-check - Verificação completa para release"
    Write-Host ""
    Write-Host "Exemplos:" -ForegroundColor Cyan
    Write-Host "  .\build.ps1 install"
    Write-Host "  .\build.ps1 test"
    Write-Host "  .\build.ps1 release-check"
}

function Install-Dependencies {
    Write-Host "📦 Instalando dependências..." -ForegroundColor Yellow
    pip install -r requirements.txt
    pip install -e .
    pip install pytest pytest-cov black isort flake8 bandit safety build twine
}

function Run-Tests {
    Write-Host "🧪 Executando testes..." -ForegroundColor Yellow
    pytest tests/ -v --cov=spectra
}

function Format-Code {
    Write-Host "🎨 Formatando código..." -ForegroundColor Yellow
    black spectra/ tests/
    isort spectra/ tests/
}

function Run-Lint {
    Write-Host "🔍 Verificando linting..." -ForegroundColor Yellow
    flake8 spectra/ --count --statistics
}

function Run-Security {
    Write-Host "🔒 Verificando segurança..." -ForegroundColor Yellow
    bandit -r spectra/
    safety check
}

function Build-Package {
    Write-Host "📦 Construindo pacote..." -ForegroundColor Yellow
    if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
    if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
    python -m build
    Write-Host "✅ Pacote construído em dist/" -ForegroundColor Green
}

function Clean-Files {
    Write-Host "🧹 Limpando arquivos temporários..." -ForegroundColor Yellow
    
    # Remove __pycache__
    Get-ChildItem -Recurse -Name "__pycache__" | Remove-Item -Recurse -Force
    
    # Remove .pyc files
    Get-ChildItem -Recurse -Name "*.pyc" | Remove-Item -Force
    
    # Remove build directories
    if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
    if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
    if (Test-Path ".coverage") { Remove-Item -Force ".coverage" }
    if (Test-Path "htmlcov") { Remove-Item -Recurse -Force "htmlcov" }
    if (Test-Path ".pytest_cache") { Remove-Item -Recurse -Force ".pytest_cache" }
    
    Write-Host "✅ Limpeza concluída" -ForegroundColor Green
}

function Run-ReleaseCheck {
    Write-Host "🚀 Executando verificação completa..." -ForegroundColor Yellow
    .\release-check.ps1
}

# Executar ação baseada no parâmetro
switch ($Action.ToLower()) {
    "help" { Show-Help }
    "install" { Install-Dependencies }
    "test" { Run-Tests }
    "format" { Format-Code }
    "lint" { Run-Lint }
    "security" { Run-Security }
    "build" { Build-Package }
    "clean" { Clean-Files }
    "release-check" { Run-ReleaseCheck }
    default { 
        Write-Host "❌ Ação desconhecida: $Action" -ForegroundColor Red
        Show-Help 
    }
}