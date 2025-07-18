#!/bin/bash
# Script de instalação para Spectra via APT

set -e

echo "🚀 Instalando Spectra Security Suite via APT..."

# Detectar distribuição
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    echo "❌ Não foi possível detectar a distribuição Linux"
    exit 1
fi

echo "📋 Sistema detectado: $OS $VER"

# Função para Ubuntu/Debian
install_ubuntu_debian() {
    echo "📦 Atualizando repositórios..."
    sudo apt update
    
    echo "📦 Instalando dependências..."
    sudo apt install -y \
        python3 \
        python3-pip \
        python3-requests \
        python3-aiohttp \
        python3-dnspython \
        python3-bs4 \
        python3-lxml \
        python3-pil \
        python3-rich \
        python3-tqdm \
        python3-cryptography \
        python3-pandas \
        python3-psutil \
        curl \
        wget \
        gnupg
    
    echo "🔑 Adicionando chave GPG do repositório Spectra..."
    curl -fsSL https://spectra-security.com/gpg-key | sudo gpg --dearmor -o /usr/share/keyrings/spectra-archive-keyring.gpg
    
    echo "📋 Adicionando repositório Spectra..."
    echo "deb [signed-by=/usr/share/keyrings/spectra-archive-keyring.gpg] https://apt.spectra-security.com/ stable main" | sudo tee /etc/apt/sources.list.d/spectra.list
    
    echo "📦 Atualizando repositórios..."
    sudo apt update
    
    echo "🚀 Instalando Spectra..."
    sudo apt install -y spectra-suite
}

# Função para outras distribuições (fallback para pip)
install_other() {
    echo "⚠️  Distribuição não suportada para instalação via APT"
    echo "📦 Instalando via pip como alternativa..."
    
    # Instalar Python e pip se necessário
    if command -v dnf &> /dev/null; then
        sudo dnf install -y python3 python3-pip
    elif command -v yum &> /dev/null; then
        sudo yum install -y python3 python3-pip
    elif command -v pacman &> /dev/null; then
        sudo pacman -S python python-pip
    elif command -v zypper &> /dev/null; then
        sudo zypper install python3 python3-pip
    else
        echo "❌ Gerenciador de pacotes não suportado"
        echo "💡 Instale Python 3 e pip manualmente, depois execute: pip install spectra-suite"
        exit 1
    fi
    
    # Instalar via pip
    pip3 install spectra-suite
}

# Executar instalação baseada na distribuição
case "$OS" in
    "Ubuntu"*)
        install_ubuntu_debian
        ;;
    "Debian"*)
        install_ubuntu_debian
        ;;
    *)
        install_other
        ;;
esac

echo "✅ Instalação concluída!"
echo ""
echo "🎯 Para testar a instalação:"
echo "   spectra --version"
echo "   spectra --help"
echo ""
echo "📚 Documentação: https://github.com/spectra-team/spectra"
echo "🛡️  Lembre-se: Use apenas para testes autorizados!"
echo ""
echo "🎉 Spectra Security Suite está pronto para uso!"