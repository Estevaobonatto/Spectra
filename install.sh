#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Spectra Security Suite — Universal Linux/macOS Installer
#
# Uso:
#   curl -fsSL https://raw.githubusercontent.com/Estevaobonatto/Spectra/main/install.sh | bash
#   bash install.sh
#   bash install.sh --uninstall
#   bash install.sh --version 2.0.1
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO="Estevaobonatto/Spectra"
VERSION="latest"
INSTALL_DIR="${HOME}/.local/bin"
UNINSTALL=false

# ── Parse args ────────────────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --uninstall)           UNINSTALL=true ;;
        --version=*)           VERSION="${arg#*=}" ;;
        --version)             shift; VERSION="${1:-latest}" ;;
        --install-dir=*)       INSTALL_DIR="${arg#*=}" ;;
        -h|--help)
            echo "Uso: bash install.sh [--version=X.Y.Z] [--install-dir=DIR] [--uninstall]"
            exit 0 ;;
    esac
done

# ── Cores ─────────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'
    YELLOW='\033[1;33m'; GRAY='\033[0;90m'; BOLD='\033[1m'; RESET='\033[0m'
else
    CYAN='' GREEN='' RED='' YELLOW='' GRAY='' BOLD='' RESET=''
fi

header() {
    echo ""
    echo -e "${CYAN}  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗  █████╗ ${RESET}"
    echo -e "${CYAN}  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗${RESET}"
    echo -e "${CYAN}  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝███████║${RESET}"
    echo -e "${CYAN}  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══██║${RESET}"
    echo -e "${CYAN}  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║██║  ██║${RESET}"
    echo -e "${CYAN}  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝${RESET}"
    echo -e "${GRAY}         Web Security Suite  —  Linux/macOS Installer${RESET}"
    echo ""
}

step()    { echo -e "  ${BOLD}»${RESET} $*"; }
success() { echo -e "  ${GREEN}✔${RESET} $*"; }
fail()    { echo -e "  ${RED}✘${RESET} $*" >&2; }
warn()    { echo -e "  ${YELLOW}!${RESET} $*"; }

# ── Detectar plataforma e arquitetura ─────────────────────────────────────────
detect_target() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux*)  PLATFORM="linux" ;;
        Darwin*) PLATFORM="macos" ;;
        *)       fail "Sistema operacional não suportado: $os"; exit 1 ;;
    esac

    case "$arch" in
        x86_64|amd64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)             fail "Arquitetura não suportada: $arch"
                       warn "Instale via pip: pip install spectra-suite"
                       exit 1 ;;
    esac

    BINARY_NAME="spectra-${PLATFORM}-${ARCH}"
    BIN_PATH="${INSTALL_DIR}/spectra"
}

# ── Resolver versão via API GitHub ────────────────────────────────────────────
resolve_version() {
    if [ "$VERSION" != "latest" ]; then
        return
    fi

    step "Consultando última versão..."
    local api_url="https://api.github.com/repos/${REPO}/releases/latest"

    if command -v curl &>/dev/null; then
        VERSION=$(curl -fsSL -H "User-Agent: spectra-installer" "$api_url" \
            | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/')
    elif command -v wget &>/dev/null; then
        VERSION=$(wget -qO- --header="User-Agent: spectra-installer" "$api_url" \
            | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/')
    else
        fail "curl ou wget é necessário para a instalação."
        exit 1
    fi

    if [ -z "$VERSION" ]; then
        fail "Não foi possível determinar a versão mais recente."
        exit 1
    fi
}

# ── Download ──────────────────────────────────────────────────────────────────
download_binary() {
    local url="https://github.com/${REPO}/releases/download/v${VERSION}/${BINARY_NAME}"
    local tmp_file
    tmp_file="$(mktemp /tmp/spectra-XXXXXX)"

    step "Baixando ${BINARY_NAME} v${VERSION}..."
    echo -e "  ${GRAY}${url}${RESET}"

    if command -v curl &>/dev/null; then
        curl -fSL --progress-bar -H "User-Agent: spectra-installer" \
            --retry 3 --retry-delay 2 \
            -o "$tmp_file" "$url"
    else
        wget -q --show-progress --header="User-Agent: spectra-installer" \
            -O "$tmp_file" "$url"
    fi

    echo "$tmp_file"
}

# ── Verificar checksum SHA-256 (opcional) ─────────────────────────────────────
verify_checksum() {
    local file="$1"
    local checksum_url="https://github.com/${REPO}/releases/download/v${VERSION}/checksums.sha256"
    local tmp_checksum
    tmp_checksum="$(mktemp /tmp/spectra-checksum-XXXXXX)"

    if curl -fsSL -o "$tmp_checksum" "$checksum_url" 2>/dev/null; then
        local expected actual
        expected=$(grep "$BINARY_NAME" "$tmp_checksum" | awk '{print $1}')
        rm -f "$tmp_checksum"

        if [ -n "$expected" ]; then
            if command -v sha256sum &>/dev/null; then
                actual=$(sha256sum "$file" | awk '{print $1}')
            elif command -v shasum &>/dev/null; then
                actual=$(shasum -a 256 "$file" | awk '{print $1}')
            fi

            if [ -n "${actual:-}" ] && [ "$actual" != "$expected" ]; then
                fail "Checksum inválido! O arquivo pode estar corrompido."
                rm -f "$file"
                exit 1
            fi
            success "Checksum SHA-256 verificado"
        fi
    else
        rm -f "$tmp_checksum"
        echo -e "  ${GRAY}(verificação de checksum ignorada)${RESET}"
    fi
}

# ── Instalar ──────────────────────────────────────────────────────────────────
do_install() {
    resolve_version
    success "Versão: v${VERSION} | Plataforma: ${PLATFORM}/${ARCH}"

    # Verificar se já está instalado e atualizado
    if [ -f "$BIN_PATH" ]; then
        existing_ver=$("$BIN_PATH" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
        if [ "${existing_ver:-}" = "$VERSION" ]; then
            success "Spectra v${VERSION} já está instalado e atualizado."
            echo ""
            return
        fi
        step "Atualizando v${existing_ver:-?} → v${VERSION}..."
    fi

    # Criar diretório de instalação
    mkdir -p "$INSTALL_DIR"

    # Download
    local tmp_bin
    tmp_bin="$(download_binary)"

    # Verificar checksum
    verify_checksum "$tmp_bin"

    # Instalar
    install -m 755 "$tmp_bin" "$BIN_PATH"
    rm -f "$tmp_bin"
    success "Binário instalado: ${BIN_PATH}"

    # Configurar PATH
    setup_path

    # Verificar
    step "Verificando instalação..."
    if "$BIN_PATH" --version &>/dev/null; then
        local installed_ver
        installed_ver=$("$BIN_PATH" --version 2>/dev/null || echo "ok")
        success "Instalação verificada: ${installed_ver}"
    else
        warn "Binário instalado mas verificação automática não disponível."
    fi

    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "   ${GREEN}${BOLD}Spectra v${VERSION} instalado com sucesso!${RESET}"
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""

    if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
        warn "Reinicie o terminal ou execute:"
        echo -e "    ${CYAN}source ~/.bashrc${RESET}   # bash"
        echo -e "    ${CYAN}source ~/.zshrc${RESET}    # zsh"
        echo ""
    fi

    echo -e "  Uso: ${CYAN}spectra --help${RESET}"
    echo -e "  Docs: ${GRAY}https://github.com/${REPO}#readme${RESET}"
    echo ""
}

# ── Configurar PATH no shell profile ─────────────────────────────────────────
setup_path() {
    local shell_profile=""
    local path_line="export PATH=\"${INSTALL_DIR}:\$PATH\""

    # Detectar shell profile
    if [ -n "${ZSH_VERSION:-}" ] || [ "${SHELL:-}" = "/bin/zsh" ]; then
        shell_profile="${HOME}/.zshrc"
    elif [ -n "${BASH_VERSION:-}" ] || [ "${SHELL:-}" = "/bin/bash" ]; then
        if [ -f "${HOME}/.bash_profile" ]; then
            shell_profile="${HOME}/.bash_profile"
        else
            shell_profile="${HOME}/.bashrc"
        fi
    elif [ -f "${HOME}/.profile" ]; then
        shell_profile="${HOME}/.profile"
    fi

    if [ -n "$shell_profile" ] && ! grep -q "$INSTALL_DIR" "$shell_profile" 2>/dev/null; then
        echo "" >> "$shell_profile"
        echo "# Spectra Security Suite" >> "$shell_profile"
        echo "$path_line" >> "$shell_profile"
        success "PATH adicionado em: $shell_profile"
        # Aplicar na sessão atual
        export PATH="${INSTALL_DIR}:${PATH}"
    fi
}

# ── Desinstalar ───────────────────────────────────────────────────────────────
do_uninstall() {
    echo ""
    echo -e "${YELLOW}  Desinstalando Spectra...${RESET}"
    echo ""

    if [ -f "$BIN_PATH" ]; then
        rm -f "$BIN_PATH"
        success "Binário removido: ${BIN_PATH}"
    else
        warn "Spectra não encontrado em: ${BIN_PATH}"
    fi

    # Remover entrada do PATH nos shell profiles
    for profile in "${HOME}/.bashrc" "${HOME}/.bash_profile" "${HOME}/.zshrc" "${HOME}/.profile"; do
        if [ -f "$profile" ] && grep -q "Spectra Security Suite" "$profile"; then
            # Remove o bloco de 3 linhas (comentário + export)
            if command -v sed &>/dev/null; then
                sed -i '/# Spectra Security Suite/,+1d' "$profile" 2>/dev/null || true
            fi
            success "Removido de: $profile"
        fi
    done

    echo ""
    echo -e "  ${YELLOW}Spectra foi desinstalado.${RESET}"
    echo ""
}

# ── Entry point ───────────────────────────────────────────────────────────────
header
detect_target

if [ "$UNINSTALL" = true ]; then
    do_uninstall
else
    do_install
fi
