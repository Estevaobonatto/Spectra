```bash
                                    d8P
                                  d888888P
 .d888b,?88,.d88b,  d8888b  d8888b  ?88'    88bd88b d888b8b
 ?8b,   `?88'  ?88 d8b_,dP d8P' `P  88P     88P'  `d8P' ?88
   `?8b   88b  d8P 88b     88b      88b    d88     88b  ,88b
`?888P'   888888P' `?888P' `?888P'  `?8b  d88'     `?88P'`88b
          88P'
         d88
         ?8P

                     by iuawsyukboasfuilj
```

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/spectra-team/spectra)
[![Python](https://img.shields.io/badge/python-3.11%2B-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-ethical%20hacking-red.svg)](SECURITY.md)

Uma ferramenta completa de hacking ético para análise de segurança web com mais de 15 módulos especializados.

Requer Python 3.11 ou 3.12.

## **Características Principais**

- **15+ Módulos de Segurança**: SQL Injection, XSS, IDOR, XXE, Command Injection, LFI/RFI
- **Scanner de Diretórios Avançado**: Competitivo com Dirsearch/Feroxbuster/Gobuster
- **Hash Cracker GPU**: 27+ algoritmos, 11 modos de ataque, aceleração CUDA/OpenCL
- **Network Monitor**: Interface similar ao Wireshark para análise de tráfego
- **Detector de Tecnologias**: 500+ tecnologias web suportadas
- **Performance Extrema**: Multi-threading, connection pooling, rate limiting adaptativo

## **Instalação**

### **Método 1: Via pip (Recomendado)**

```bash
# Instalação global
pip install spectra-suite

# Instalação para usuário atual
pip install --user spectra-suite

# Instalação em ambiente virtual
python -m venv spectra-env
source spectra-env/bin/activate  # Linux/Mac
# ou spectra-env\Scripts\activate  # Windows
pip install spectra-suite
```

### **Método 2: Via APT (Ubuntu/Debian)**

```bash
# Download e execução do script de instalação
curl -fsSL https://raw.githubusercontent.com/spectra-team/spectra/main/install-apt.sh | bash

# Ou manualmente:
wget https://raw.githubusercontent.com/spectra-team/spectra/main/install-apt.sh
chmod +x install-apt.sh
./install-apt.sh
```

### **Método 3: Via código fonte**

```bash
git clone https://github.com/spectra-team/spectra.git
cd spectra
pip install -r requirements.txt
python setup.py install

# Via APT

```

### **Verificar instalação:**

```bash
spectra --version
spectra --help
```

## **Uso Básico**

```bash
# Scan completo de vulnerabilidades
spectra -bvs https://example.com --verbose

# SQL Injection avançado
spectra -sqli http://example.com/page?id=1 --sqli-level 3

# Directory scanner competitivo
spectra -ds https://example.com -w wordlist.txt --recursive --performance-mode aggressive

# Hash cracking com GPU
spectra -hc 5d41402abc4b2a76b9719d911017c592 --use-gpu --attack-mode all

# Network monitoring
spectra -nm
```

## **Documentação Completa**

- [Guia de Instalação](docs/installation.md)
- [Manual de Uso](docs/usage.md)
- [Exemplos Práticos](docs/examples.md)
- [API Reference](docs/api.md)

## **Aviso Legal**

Esta ferramenta é destinada EXCLUSIVAMENTE para:

- Testes de penetração autorizados
- Pesquisa de segurança
- Educação em cibersegurança
- Auditoria de segurança própria

O uso não autorizado é ILEGAL e pode resultar em consequências legais.

## 🤝 **Contribuindo**

Veja [CONTRIBUTING.md](CONTRIBUTING.md) para detalhes sobre como contribuir.

## **Licença**

Este projeto está licenciado sob a Licença MIT - veja [LICENSE](LICENSE) para detalhes.

## **Segurança**

Para relatar vulnerabilidades de segurança, veja [SECURITY.md](SECURITY.md).
