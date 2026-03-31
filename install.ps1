#Requires -Version 5.1
<#
.SYNOPSIS
    Instalador do Spectra Security Suite para Windows.

.DESCRIPTION
    Baixa o binário mais recente do GitHub Releases, instala em
    $env:LOCALAPPDATA\Programs\Spectra e adiciona ao PATH do usuário.

.EXAMPLE
    # Instalar (modo padrão)
    irm https://raw.githubusercontent.com/Estevaobonatto/Spectra/main/install.ps1 | iex

    # Ou baixar e rodar localmente
    .\install.ps1

    # Desinstalar
    .\install.ps1 -Uninstall

.NOTES
    Não requer privilégios de administrador.
    Suporte: Windows 10/11, Windows Server 2019+.
#>

[CmdletBinding()]
param(
    [switch]$Uninstall,
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\Spectra"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Constantes ────────────────────────────────────────────────────────────────
$REPO       = "Estevaobonatto/Spectra"
$BINARY     = "spectra-windows-amd64.exe"
$EXE_NAME   = "spectra.exe"
$BIN_PATH   = Join-Path $InstallDir $EXE_NAME

# ── Funções auxiliares ────────────────────────────────────────────────────────
function Write-Header {
    Write-Host ""
    Write-Host "  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗  █████╗ " -ForegroundColor Cyan
    Write-Host "  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗" -ForegroundColor Cyan
    Write-Host "  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝███████║" -ForegroundColor Cyan
    Write-Host "  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══██║" -ForegroundColor Cyan
    Write-Host "  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║██║  ██║" -ForegroundColor Cyan
    Write-Host "  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝" -ForegroundColor Cyan
    Write-Host "           Web Security Suite  —  Windows Installer" -ForegroundColor DarkGray
    Write-Host ""
}

function Write-Step([string]$msg) {
    Write-Host "  » $msg" -ForegroundColor White
}

function Write-Success([string]$msg) {
    Write-Host "  ✔ $msg" -ForegroundColor Green
}

function Write-Fail([string]$msg) {
    Write-Host "  ✘ $msg" -ForegroundColor Red
}

function Get-LatestVersion {
    $uri = "https://api.github.com/repos/$REPO/releases/latest"
    try {
        $headers = @{ "User-Agent" = "spectra-installer" }
        $release = Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec 15
        return $release.tag_name.TrimStart("v")
    } catch {
        Write-Fail "Não foi possível consultar a versão mais recente: $_"
        exit 1
    }
}

function Get-DownloadUrl([string]$ver) {
    return "https://github.com/$REPO/releases/download/v$ver/$BINARY"
}

function Get-ChecksumUrl([string]$ver) {
    return "https://github.com/$REPO/releases/download/v$ver/checksums.sha256"
}

function Add-ToUserPath([string]$dir) {
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($currentPath -notlike "*$dir*") {
        $newPath = "$dir;$currentPath"
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
        # Atualiza PATH da sessão atual também
        $env:PATH = "$dir;$env:PATH"
        return $true
    }
    return $false
}

function Remove-FromUserPath([string]$dir) {
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    $newPath = ($currentPath -split ";" | Where-Object { $_ -ne $dir }) -join ";"
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
}

function Test-CommandExists([string]$cmd) {
    return $null -ne (Get-Command $cmd -ErrorAction SilentlyContinue)
}

# ── Desinstalação ─────────────────────────────────────────────────────────────
function Invoke-Uninstall {
    Write-Header
    Write-Host "  Desinstalando Spectra..." -ForegroundColor Yellow
    Write-Host ""

    if (Test-Path $InstallDir) {
        Remove-Item $InstallDir -Recurse -Force
        Write-Success "Arquivos removidos: $InstallDir"
    } else {
        Write-Host "  Spectra não encontrado em $InstallDir" -ForegroundColor DarkGray
    }

    Remove-FromUserPath $InstallDir
    Write-Success "PATH do usuário atualizado"
    Write-Host ""
    Write-Host "  Spectra foi desinstalado." -ForegroundColor Yellow
    Write-Host ""
}

# ── Instalação ────────────────────────────────────────────────────────────────
function Invoke-Install {
    Write-Header

    # Resolver versão
    if ($Version -eq "latest") {
        Write-Step "Consultando última versão..."
        $Version = Get-LatestVersion
    }
    Write-Success "Versão: v$Version"

    # Verificar instalação existente
    if (Test-Path $BIN_PATH) {
        try {
            $existingVer = & $BIN_PATH --version 2>&1 | Select-String -Pattern "[\d]+\.[\d]+\.[\d]+" | ForEach-Object { $_.Matches[0].Value }
            if ($existingVer -eq $Version) {
                Write-Success "Spectra v$Version já está instalado e atualizado."
                Write-Host ""
                return
            }
            Write-Step "Atualizando v$existingVer → v$Version..."
        } catch {
            Write-Step "Reinstalando v$Version..."
        }
    }

    # Criar diretório
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        Write-Success "Diretório criado: $InstallDir"
    }

    # Download do binário
    $downloadUrl = Get-DownloadUrl $Version
    $tmpFile     = Join-Path $env:TEMP "spectra-tmp-$Version.exe"

    Write-Step "Baixando $BINARY..."
    Write-Host "    $downloadUrl" -ForegroundColor DarkGray

    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("User-Agent", "spectra-installer")
        $wc.DownloadFile($downloadUrl, $tmpFile)
    } catch {
        Write-Fail "Falha no download: $_"
        Write-Host ""
        Write-Host "  Alternativa: instale via pip" -ForegroundColor Yellow
        Write-Host "    pip install spectra-suite" -ForegroundColor DarkGray
        exit 1
    }

    # Verificar checksum SHA-256 (se disponível)
    $checksumUrl = Get-ChecksumUrl $Version
    try {
        $checksumContent = (Invoke-RestMethod -Uri $checksumUrl -TimeoutSec 10 -ErrorAction Stop)
        $expectedHash = ($checksumContent -split "`n" | Where-Object { $_ -match $BINARY } | Select-Object -First 1) -replace "\s+.*", ""
        if ($expectedHash) {
            $actualHash = (Get-FileHash $tmpFile -Algorithm SHA256).Hash.ToLower()
            if ($actualHash -ne $expectedHash.ToLower()) {
                Write-Fail "Checksum inválido! O arquivo pode estar corrompido."
                Remove-Item $tmpFile -Force
                exit 1
            }
            Write-Success "Checksum SHA-256 verificado"
        }
    } catch {
        # Checksum opcional — continua sem verificar
        Write-Host "  (verificação de checksum ignorada)" -ForegroundColor DarkGray
    }

    # Instalar binário
    Copy-Item $tmpFile $BIN_PATH -Force
    Remove-Item $tmpFile -Force
    Write-Success "Binário instalado: $BIN_PATH"

    # Adicionar ao PATH
    $added = Add-ToUserPath $InstallDir
    if ($added) {
        Write-Success "PATH do usuário atualizado"
    }

    # Verificar instalação
    Write-Step "Verificando instalação..."
    try {
        $verOutput = & $BIN_PATH --version 2>&1
        Write-Success "Instalação verificada: $verOutput"
    } catch {
        Write-Host "  (verificação automática indisponível)" -ForegroundColor DarkGray
    }

    # Resultado final
    Write-Host ""
    Write-Host "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "   Spectra v$Version instalado com sucesso!" -ForegroundColor Green
    Write-Host "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Reinicie o terminal e execute:" -ForegroundColor White
    Write-Host "    spectra --help" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Documentação: https://github.com/$REPO#readme" -ForegroundColor DarkGray
    Write-Host ""
}

# ── Entry point ───────────────────────────────────────────────────────────────
if ($Uninstall) {
    Invoke-Uninstall
} else {
    Invoke-Install
}
