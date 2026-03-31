# Script PowerShell para build rápido
# Para Windows - equivalente aos comandos make

param(
    [string]$Action = "help"
)

function Show-Help {
    Write-Host "🔧 Scripts de Build - Spectra v2.0.1" -ForegroundColor Green
    Write-Host "Uso: .\build.ps1 <ação>"
    Write-Host ""
    Write-Host "Ações disponíveis:" -ForegroundColor Yellow
    Write-Host "  help     - Mostra esta ajuda"
    Write-Host "  install  - Instala dependências de dev"
    Write-Host "  test     - Executa testes"
    Write-Host "  format   - Formata código (black + isort)"
    Write-Host "  lint     - Verifica linting (flake8)"
    Write-Host "  security - Auditoria de segurança (bandit + pip-audit)"
    Write-Host "  build    - Constrói pacote wheel + sdist"
    Write-Host "  clean    - Limpa artefatos temporários"
    Write-Host ""
    Write-Host "Para releases: crie uma tag git e o CI/CD cuida do resto." -ForegroundColor DarkGray
    Write-Host "  git tag v2.0.1 && git push origin main --tags" -ForegroundColor Cyan
}

function Install-Dependencies {
    Write-Host "📦 Instalando dependências..." -ForegroundColor Yellow
    pip install -r requirements.txt
    pip install -e .
    pip install pytest pytest-cov black isort flake8 bandit pip-audit build twine
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
    bandit -r spectra/ -c .bandit
    pip-audit
}

function Build-Package {
    Write-Host "📦 Construindo pacote..." -ForegroundColor Yellow
    if (Test-Path "dist") { 
        Remove-Item -Recurse -Force "dist" 
    }
    if (Test-Path "build") { 
        Remove-Item -Recurse -Force "build" 
    }
    python -m build
    Write-Host "✅ Pacote construído em dist/" -ForegroundColor Green
}

function Clean-Files {
    Write-Host "🧹 Limpando arquivos temporários..." -ForegroundColor Yellow
    
    # Remove __pycache__
    Get-ChildItem -Recurse -Name "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    
    # Remove .pyc files
    Get-ChildItem -Recurse -Name "*.pyc" | Remove-Item -Force -ErrorAction SilentlyContinue
    
    # Remove build directories
    if (Test-Path "build") { 
        Remove-Item -Recurse -Force "build" 
    }
    if (Test-Path "dist") { 
        Remove-Item -Recurse -Force "dist" 
    }
    if (Test-Path ".coverage") { 
        Remove-Item -Force ".coverage" 
    }
    if (Test-Path "htmlcov") { 
        Remove-Item -Recurse -Force "htmlcov" 
    }
    if (Test-Path ".pytest_cache") { 
        Remove-Item -Recurse -Force ".pytest_cache" 
    }
    
    Write-Host "✅ Limpeza concluída" -ForegroundColor Green
}

# Executar ação baseada no parâmetro
switch ($Action.ToLower()) {
    "help" { 
        Show-Help 
    }
    "install" { 
        Install-Dependencies 
    }
    "test" { 
        Run-Tests 
    }
    "format" { 
        Format-Code 
    }
    "lint" { 
        Run-Lint 
    }
    "security" { 
        Run-Security 
    }
    "build" { 
        Build-Package 
    }
    "clean" { 
        Clean-Files 
    }
    default { 
        Write-Host "❌ Ação desconhecida: $Action" -ForegroundColor Red
        Show-Help 
    }
}