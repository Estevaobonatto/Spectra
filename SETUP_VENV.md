# 🚀 Configuração do Ambiente Virtual Python (.venv) - Spectra

## ✅ Status da Configuração
O ambiente virtual Python (.venv) foi configurado com sucesso no projeto Spectra!

## 📋 Comandos Para Ativação Manual

### No PowerShell (Windows):
```powershell
# Navegar até o diretório do projeto
cd h:\Projetos\Spectra

# Ativar o ambiente virtual
.venv\Scripts\activate

# Verificar se está ativo (deve mostrar (.venv) no prompt)
python --version
```

### No CMD (Windows):
```cmd
# Navegar até o diretório do projeto
cd h:\Projetos\Spectra

# Ativar o ambiente virtual
.venv\Scripts\activate.bat

# Verificar se está ativo
python --version
```

## 🔧 Informações do Ambiente

- **Tipo**: VirtualEnvironment
- **Versão Python**: 3.12.10
- **Localização**: `h:\Projetos\Spectra\.venv`
- **Executável Python**: `H:/Projetos/Spectra/.venv/Scripts/python.exe`

## 📦 Dependências Instaladas

Todas as dependências foram instaladas automaticamente:

- **requests**: HTTP requests
- **beautifulsoup4**: Web scraping
- **selenium**: Web automation
- **dnspython**: DNS queries
- **python-whois**: WHOIS analysis
- **pillow**: Image processing
- **rich**: Terminal formatting
- **colorama**: Terminal colors
- **tqdm**: Progress bars
- **cryptography**: Security tools
- **pyOpenSSL**: SSL/TLS analysis

## 🎯 Como Usar o Spectra

### 1. Via Módulo Python:
```powershell
# Certifique-se de que o ambiente virtual está ativo
python -m spectra --help
python -m spectra --version
python -m spectra -dns google.com
python -m spectra -ps google.com -p 80,443
```

### 2. Via Script Principal:
```powershell
python main.py --help
python main.py -dns google.com
python main.py -ps google.com -p 80,443
```

## 🧪 Executar Testes
```powershell
# Executar todos os testes da estrutura modular
python test_structure.py
```

## 🔄 Comandos Úteis

### Instalar Novas Dependências:
```powershell
# Instalar uma nova dependência
pip install nome_da_dependencia

# Atualizar requirements.txt
pip freeze > requirements.txt
```

### Desativar Ambiente Virtual:
```powershell
deactivate
```

### Reinstalar Dependências:
```powershell
# Se precisar reinstalar tudo
pip install -r requirements.txt
pip install -e .
```

## 🏗️ Estrutura do Projeto

```
h:\Projetos\Spectra\
├── .venv/                    # Ambiente virtual Python
├── spectra/                  # Pacote principal
│   ├── __init__.py
│   ├── __main__.py          # Entry point para python -m spectra
│   ├── core/                # Componentes principais
│   │   ├── config.py
│   │   ├── console.py
│   │   ├── banner.py
│   │   └── logger.py
│   ├── modules/             # Módulos de funcionalidade
│   │   ├── port_scanner.py
│   │   ├── dns_analyzer.py
│   │   ├── subdomain_scanner.py
│   │   └── ...
│   ├── utils/               # Utilitários
│   │   ├── network.py
│   │   ├── parsers.py
│   │   └── validators.py
│   └── cli/                 # Interface CLI
│       └── main.py
├── main.py                  # Script principal
├── test_structure.py        # Testes automatizados
├── requirements.txt         # Dependências
└── setup.py                # Configuração do pacote
```

## 🎉 Exemplos de Uso

### Scan de Portas:
```powershell
python -m spectra -ps google.com -p 80,443,22,21
```

### Análise DNS:
```powershell
python -m spectra -dns google.com
```

### Scan de Subdomínios:
```powershell
python -m spectra -ss google.com -w wordlist.txt
```

### Scan de Diretórios:
```powershell
python -m spectra -ds http://example.com -w wordlist.txt
```

### Análise WHOIS:
```powershell
python -m spectra -whois google.com --security-analysis
```

## 📚 Próximos Passos

1. **Migrar Módulos Restantes**: Ainda há módulos do script original que precisam ser migrados
2. **Adicionar Testes Unitários**: Criar testes específicos para cada módulo
3. **Documentação**: Criar documentação detalhada para cada módulo
4. **Otimizações**: Melhorar performance e adicionar cache
5. **Novos Recursos**: Adicionar novas funcionalidades de segurança

## 🔧 Troubleshooting

### Problema: Ambiente virtual não ativa
```powershell
# Recriar ambiente virtual
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

### Problema: Dependências não encontradas
```powershell
# Reinstalar dependências
pip install -r requirements.txt
pip install -e .
```

### Problema: Comando não encontrado
```powershell
# Verificar se está no diretório correto
cd h:\Projetos\Spectra

# Verificar se o ambiente virtual está ativo
.venv\Scripts\activate
```

---

## ✅ Configuração Completa!

Seu ambiente virtual Python (.venv) está configurado e funcionando perfeitamente! 🎉

O projeto Spectra foi refatorado com sucesso de um script monolítico para uma estrutura modular profissional, com todos os módulos principais funcionando corretamente.
