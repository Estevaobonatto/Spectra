# 🎯 IDOR Scanner - Documentação Completa

## ✅ IMPLEMENTAÇÃO CONCLUÍDA

O **IDOR (Insecure Direct Object Reference) Scanner** foi **completamente implementado** no Spectra, oferecendo detecção avançada de vulnerabilidades de referência direta a objetos.

## 🚀 O que é IDOR?

IDOR é uma vulnerabilidade que ocorre quando uma aplicação fornece acesso direto a objetos baseado em input do usuário. Atacantes podem manipular parâmetros para acessar dados não autorizados.

**Exemplos de IDOR:**
- `http://site.com/profile?id=123` → `http://site.com/profile?id=124`
- `http://api.com/user/456` → `http://api.com/user/457`
- `http://app.com/document?doc_id=abc123` → `http://app.com/document?doc_id=abc124`

## 🎯 Funcionalidades Implementadas

### 1. **Detecção Automática de Parâmetros**
- ✅ **Parâmetros URL**: Detecta automaticamente parâmetros que podem conter IDs
- ✅ **IDs no Path**: Extrai IDs do caminho da URL (ex: `/user/123/profile`)
- ✅ **Padrões Comuns**: Reconhece `id`, `user_id`, `doc_id`, `file_id`, etc.

### 2. **Múltiplos Tipos de ID**
- 🔢 **IDs Numéricos**: Sequenciais, negativos, grandes números
- 🆔 **UUIDs**: Comuns, previsíveis e aleatórios
- 🔐 **Hashes**: MD5, SHA1, SHA256 (comuns e derivados)
- 📝 **IDs String**: admin, root, test, guest, etc.
- 🔤 **IDs Codificados**: Base64, URL encoding

### 3. **Análise Avançada de Respostas**
- 📊 **Comparação de Status**: Detecta mudanças de 404→200, 403→200
- 📏 **Análise de Tamanho**: Identifica diferenças significativas no conteúdo
- 🔍 **Detecção de Dados Sensíveis**: Email, telefone, SSN, cartão de crédito
- 📋 **Análise JSON/XML**: Procura campos sensíveis em dados estruturados

### 4. **Métodos HTTP Múltiplos**
- 🌐 **GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS**
- 🔄 **Teste Paralelo**: Testa todos os métodos simultaneamente
- ⚡ **Performance Otimizada**: Threading configurável

### 5. **Classificação de Severidade**
- 🔴 **CRÍTICA**: Dados muito sensíveis (senhas, chaves privadas, saldo)
- 🟠 **ALTA**: Dados pessoais (email, telefone, endereço)
- 🟡 **MÉDIA**: Acesso não autorizado confirmado
- 🔵 **BAIXA**: Possível exposição de objetos

## 📋 Comandos CLI Implementados

### Uso Básico
```bash
# Teste básico com range de IDs
spectra -idor http://example.com/user?id=123 --idor-range 1-100

# Teste com ID no path
spectra -idor http://api.com/users/456 --idor-range 1-1000
```

### Testes Avançados
```bash
# Inclui UUIDs e hashes
spectra -idor http://app.com/profile/789 --test-uuid --test-hash

# Wordlist customizada
spectra -idor http://site.com/doc?doc_id=abc --idor-wordlist custom_ids.txt

# Múltiplos métodos HTTP
spectra -idor http://api.com/resource/123 --idor-methods GET,POST,PUT,DELETE
```

### Performance Otimizada
```bash
# Configurações de performance
spectra -idor http://fast.com/item/456 --workers 50 --idor-delay 0.05

# Range grande com otimizações
spectra -idor http://big.com/user?id=1000 --idor-range 1-10000 --workers 100
```

## 🔧 Parâmetros Disponíveis

| Parâmetro | Descrição | Exemplo |
|-----------|-----------|---------|
| `-idor URL` | URL alvo para teste IDOR | `http://site.com/user?id=123` |
| `--idor-range START-END` | Range de IDs numéricos | `--idor-range 1-1000` |
| `--test-uuid` | Inclui testes com UUIDs | `--test-uuid` |
| `--test-hash` | Inclui testes com hashes | `--test-hash` |
| `--idor-wordlist FILE` | Wordlist customizada | `--idor-wordlist ids.txt` |
| `--idor-methods METHODS` | Métodos HTTP para teste | `--idor-methods GET,POST,PUT` |
| `--idor-delay SECONDS` | Delay entre requisições | `--idor-delay 0.1` |
| `--workers N` | Número de threads | `--workers 20` |

## 📊 Saída do Scanner

### Estatísticas de Scan
```
╭─────────────────────────────────────────────────────────────╮
│                    Estatísticas do Scan                     │
├─────────────────────────────────────────────────────────────┤
│ Tempo de Scan              │ 45.23s                         │
│ Total de Requisições       │ 2,847                          │
│ Requisições Bem-sucedidas  │ 2,791                          │
│ Vulnerabilidades Encontradas │ 12                           │
│ Taxa de Sucesso            │ 98.0%                          │
╰─────────────────────────────────────────────────────────────╯
```

### Vulnerabilidades por Severidade
```
VULNERABILIDADES CRÍTICAS (3)
╭──────────────────────────────────────────────────────────────╮
│ URL                    │ Método │ Parâmetro │ Status │ Indicadores │
├────────────────────────┼────────┼───────────┼────────┼─────────────┤
│ http://site.com/u...   │ GET    │ user_id   │ 200    │ Dados sen...│
│ http://api.com/pr...   │ POST   │ profile_id│ 200    │ Email det...│
╰──────────────────────────────────────────────────────────────╯
```

## 🎯 Casos de Uso Comuns

### 1. **APIs REST**
```bash
# Teste de endpoints de API
spectra -idor http://api.company.com/users/123 --idor-range 1-1000
spectra -idor http://api.app.com/orders?order_id=456 --test-uuid
```

### 2. **Aplicações Web**
```bash
# Perfis de usuário
spectra -idor http://social.com/profile?id=789 --idor-range 1-10000

# Documentos e arquivos
spectra -idor http://docs.com/file?file_id=abc123 --test-hash
```

### 3. **Sistemas Administrativos**
```bash
# Painéis admin
spectra -idor http://admin.site.com/user/456 --idor-methods GET,POST,PUT,DELETE

# Relatórios e dados sensíveis
spectra -idor http://reports.com/view?report_id=789 --test-uuid --test-hash
```

## 🔍 Detecção de Padrões

### Parâmetros Detectados Automaticamente
- `id`, `user_id`, `userid`, `uid`
- `account_id`, `profile_id`, `doc_id`
- `file_id`, `item_id`, `product_id`
- `order_id`, `invoice_id`, `ticket_id`
- `message_id`, `post_id`, `comment_id`
- `session_id`, `token`, `key`, `ref`

### Dados Sensíveis Detectados
- **Emails**: `email@domain.com`
- **Telefones**: `(123) 456-7890`
- **SSN**: `123-45-6789`
- **Cartões**: `credit card`, `4111-1111-1111-1111`
- **Endereços**: `address: 123 Main St`
- **Chaves**: `private key`, `api key`, `secret key`
- **Financeiro**: `balance: $1000`, `salary: $50000`

## ⚡ Performance e Otimizações

### Threading Inteligente
- **Auto-ajuste**: Baseado no número de CPUs disponíveis
- **Pool de Conexões**: Reutilização de conexões HTTP
- **Rate Limiting**: Adaptativo baseado em respostas 429/503
- **Memory Management**: Controle de uso de memória

### Configurações de Performance
```bash
# Modo balanceado (padrão)
spectra -idor http://site.com/user/123 --workers 10 --idor-delay 0.1

# Modo rápido
spectra -idor http://fast.com/item/456 --workers 50 --idor-delay 0.05

# Modo agressivo
spectra -idor http://target.com/doc/789 --workers 100 --idor-delay 0.01
```

## 🛡️ Considerações de Segurança

### Rate Limiting Respeitoso
- **Delay Configurável**: Entre 0.01s e 5.0s
- **Detecção de Rate Limit**: Ajuste automático baseado em 429/503
- **Modo Stealth**: Delays maiores para evitar detecção

### Uso Ético
- ⚠️ **Sempre obtenha autorização** antes de testar
- 🎯 **Use apenas em sistemas próprios** ou com permissão explícita
- 📋 **Documente achados** de forma responsável
- 🔒 **Não acesse dados sensíveis** desnecessariamente

## 🔧 Integração com Spectra

### Módulo Independente
```python
from spectra.modules.idor_scanner import idor_scan

vulnerabilities = idor_scan(
    url="http://example.com/user?id=123",
    enumerate_range=(1, 100),
    test_uuid=True,
    test_hash=True
)
```

### CLI Integrada
```bash
# Integração completa com outras funcionalidades
spectra -idor http://target.com/api/user/123 --generate-report idor_results.html
```

## 📈 Comparação com Outras Ferramentas

| Funcionalidade | Spectra IDOR | Burp Suite | OWASP ZAP | Autorize |
|----------------|--------------|------------|-----------|----------|
| Auto-detecção de parâmetros | ✅ | ✅ | ❌ | ❌ |
| IDs no path | ✅ | ❌ | ❌ | ❌ |
| Teste de UUIDs | ✅ | ❌ | ❌ | ❌ |
| Teste de hashes | ✅ | ❌ | ❌ | ❌ |
| Múltiplos métodos HTTP | ✅ | ✅ | ✅ | ✅ |
| Análise de dados sensíveis | ✅ | ❌ | ❌ | ❌ |
| Classificação de severidade | ✅ | ✅ | ✅ | ❌ |
| Threading otimizado | ✅ | ✅ | ❌ | ❌ |
| CLI standalone | ✅ | ❌ | ❌ | ❌ |
| Gratuito | ✅ | ❌ | ✅ | ✅ |

## 🎯 Conclusão

O **IDOR Scanner do Spectra** oferece uma solução completa e profissional para detecção de vulnerabilidades IDOR, com funcionalidades avançadas que rivalizam com ferramentas comerciais. A implementação inclui:

- ✅ **Detecção automática** inteligente
- ✅ **Múltiplos tipos de ID** suportados
- ✅ **Análise avançada** de respostas
- ✅ **Performance otimizada** com threading
- ✅ **Classificação de severidade** precisa
- ✅ **Integração completa** com o Spectra
- ✅ **Interface CLI** intuitiva
- ✅ **Relatórios detalhados** profissionais

O scanner está pronto para uso em **pentests profissionais** e **auditorias de segurança**, oferecendo uma ferramenta poderosa e gratuita para a comunidade de segurança cibernética.