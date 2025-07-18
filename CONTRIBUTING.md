# 🤝 Contribuindo para o Spectra

Obrigado por considerar contribuir para o Spectra! Este documento fornece diretrizes para contribuições.

## 📋 Código de Conduta

Este projeto adere ao [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). Ao participar, você deve seguir este código.

## 🚀 Como Contribuir

### 🐛 Reportando Bugs

1. **Verifique** se o bug já foi reportado nos [Issues](https://github.com/spectra-team/spectra/issues)
2. **Crie** um novo issue com:
   - Título claro e descritivo
   - Passos para reproduzir
   - Comportamento esperado vs atual
   - Versão do Spectra e Python
   - Sistema operacional
   - Logs relevantes

### 💡 Sugerindo Melhorias

1. **Verifique** se a sugestão já existe
2. **Crie** um issue com:
   - Título claro
   - Descrição detalhada da melhoria
   - Justificativa (por que é útil)
   - Exemplos de uso

### 🔧 Contribuindo com Código

#### Configuração do Ambiente

```bash
# Clone o repositório
git clone https://github.com/spectra-team/spectra.git
cd spectra

# Crie um ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# Instale dependências de desenvolvimento
pip install -r requirements.txt
pip install -e .[dev]
```

#### Fluxo de Desenvolvimento

1. **Fork** o repositório
2. **Crie** uma branch para sua feature:
   ```bash
   git checkout -b feature/nova-funcionalidade
   ```
3. **Faça** suas alterações
4. **Execute** os testes:
   ```bash
   pytest tests/
   ```
5. **Verifique** a qualidade do código:
   ```bash
   black spectra/
   isort spectra/
   flake8 spectra/
   bandit -r spectra/
   ```
6. **Commit** suas alterações:
   ```bash
   git commit -m "feat: adiciona nova funcionalidade"
   ```
7. **Push** para sua branch:
   ```bash
   git push origin feature/nova-funcionalidade
   ```
8. **Abra** um Pull Request

#### Padrões de Commit

Usamos [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` nova funcionalidade
- `fix:` correção de bug
- `docs:` documentação
- `style:` formatação
- `refactor:` refatoração
- `test:` testes
- `chore:` tarefas de manutenção

## 🧪 Testes

### Executando Testes

```bash
# Todos os testes
pytest

# Com coverage
pytest --cov=spectra

# Testes específicos
pytest tests/test_basic_vulnerability_scanner.py

# Testes por categoria
pytest -m unit
pytest -m integration
```

### Escrevendo Testes

- **Unit tests**: Para funções individuais
- **Integration tests**: Para módulos completos
- **Mock**: Use para dependências externas
- **Coverage**: Mantenha acima de 80%

Exemplo:
```python
def test_vulnerability_detection():
    scanner = BasicVulnerabilityScanner("https://example.com")
    vulnerabilities = scanner.scan()
    assert len(vulnerabilities) >= 0
```

## 📝 Documentação

### Docstrings

Use o formato Google:

```python
def scan_vulnerabilities(url: str, timeout: int = 10) -> List[Vulnerability]:
    """Executa scan de vulnerabilidades.
    
    Args:
        url: URL alvo para o scan
        timeout: Timeout em segundos
        
    Returns:
        Lista de vulnerabilidades encontradas
        
    Raises:
        ValueError: Se URL for inválida
    """
```

### README e Docs

- Mantenha o README.md atualizado
- Adicione exemplos práticos
- Documente novas funcionalidades

## 🏗️ Arquitetura

### Estrutura de Módulos

```
spectra/
├── cli/           # Interface de linha de comando
├── core/          # Funcionalidades centrais
├── modules/       # Módulos de scanning
├── utils/         # Utilitários
└── data/          # Dados estáticos
```

### Criando Novos Módulos

1. **Crie** o arquivo em `spectra/modules/`
2. **Implemente** a interface padrão
3. **Adicione** metadata estruturada
4. **Escreva** testes
5. **Documente** o uso

Exemplo:
```python
from spectra.core.module_metadata import ModuleMetadata, Parameter

class NovoScanner:
    def __init__(self, url: str):
        self.url = url
    
    def scan(self) -> List[Vulnerability]:
        """Executa o scan"""
        pass
    
    @staticmethod
    def get_metadata() -> ModuleMetadata:
        """Retorna metadata do módulo"""
        return ModuleMetadata(
            name="novo_scanner",
            display_name="Novo Scanner",
            description="Descrição do scanner",
            # ... outros campos
        )
```

## 🔒 Segurança

### Diretrizes

- **Nunca** commite credenciais
- **Valide** todas as entradas
- **Sanitize** outputs para logs
- **Use** HTTPS quando possível
- **Implemente** rate limiting

### Revisão de Segurança

Todas as contribuições passam por:

1. **Análise estática** (Bandit)
2. **Verificação de dependências** (Safety)
3. **Code review** manual
4. **Testes de segurança**

## 🎯 Prioridades

### Alta Prioridade

- 🐛 Correções de bugs críticos
- 🔒 Vulnerabilidades de segurança
- 📚 Melhorias na documentação
- 🧪 Aumento da cobertura de testes

### Média Prioridade

- ✨ Novas funcionalidades
- 🚀 Melhorias de performance
- 🎨 Melhorias na UX/UI
- 🔧 Refatorações

### Baixa Prioridade

- 🎨 Melhorias cosméticas
- 📝 Documentação adicional
- 🧹 Limpeza de código

## 📞 Contato

- **Issues**: [GitHub Issues](https://github.com/spectra-team/spectra/issues)
- **Discussions**: [GitHub Discussions](https://github.com/spectra-team/spectra/discussions)
- **Email**: contribute@spectra-team.com
- **Discord**: [Spectra Community](https://discord.gg/spectra)

## 🏆 Reconhecimento

Contribuidores são reconhecidos:

- 📜 **CONTRIBUTORS.md**: Lista de todos os contribuidores
- 🎖️ **Releases**: Créditos em notas de release
- 🌟 **GitHub**: Stars e follows
- 🎁 **Swag**: Brindes para contribuidores ativos

---

**Obrigado por contribuir para tornar a web mais segura! 🛡️**