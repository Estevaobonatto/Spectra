# 🔍 Spectra - Web Security Suite

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/spectra-team/spectra)
[![Python](https://img.shields.io/badge/python-3.6+-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-ethical%20hacking-red.svg)](SECURITY.md)

Uma ferramenta completa de hacking ético para análise de segurança web com mais de 15 módulos especializados.

## **Características Principais**

- **15+ Módulos de Segurança**: SQL Injection, XSS, IDOR, XXE, Command Injection, LFI/RFI
- **Scanner de Diretórios Avançado**: Competitivo com Dirsearch/Feroxbuster/Gobuster
- **Hash Cracker GPU**: 27+ algoritmos, 11 modos de ataque, aceleração CUDA/OpenCL
- **Network Monitor**: Interface similar ao Wireshark para análise de tráfego
- **Detector de Tecnologias**: 500+ tecnologias web suportadas
- **Performance Extrema**: Multi-threading, connection pooling, rate limiting adaptativo

## **Instalação Rápida**

```bash
# Via pip (recomendado)
pip install spectra-suite

# Via código fonte
git clone https://github.com/spectra-team/spectra.git
cd spectra
pip install -r requirements.txt
python setup.py install
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