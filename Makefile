# Makefile para automação de tarefas

.PHONY: help install install-dev test lint format security clean build upload docs

help:  ## Mostra esta ajuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Instala dependências de produção
	pip install -r requirements.txt
	pip install -e .

install-dev:  ## Instala dependências de desenvolvimento
	pip install -r requirements.txt
	pip install -e .[dev]

test:  ## Executa todos os testes
	pytest tests/ -v --cov=spectra --cov-report=html --cov-report=term

test-fast:  ## Executa testes rápidos (sem integração)
	pytest tests/ -v -m "not slow" --cov=spectra

lint:  ## Executa linting (flake8)
	flake8 spectra/ --count --statistics
	flake8 tests/ --count --statistics

format:  ## Formata código (black + isort)
	black spectra/ tests/
	isort spectra/ tests/

format-check:  ## Verifica formatação sem alterar
	black --check spectra/ tests/
	isort --check-only spectra/ tests/

security:  ## Executa verificações de segurança
	bandit -r spectra/ -f json -o bandit-report.json
	safety check --json --output safety-report.json

security-report:  ## Mostra relatório de segurança
	bandit -r spectra/
	safety check

clean:  ## Remove arquivos temporários
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/ dist/ .coverage htmlcov/ .pytest_cache/
	rm -f bandit-report.json safety-report.json

build:  ## Constrói pacote para distribuição
	python -m build

upload-test:  ## Upload para TestPyPI
	python -m twine upload --repository testpypi dist/*

upload:  ## Upload para PyPI
	python -m twine upload dist/*

docs:  ## Gera documentação
	@echo "Documentação disponível em README.md"
	@echo "Para documentação completa, visite: https://spectra-security.readthedocs.io"

pre-commit:  ## Executa verificações antes do commit
	make format-check
	make lint
	make security
	make test-fast

ci:  ## Simula pipeline de CI localmente
	make format-check
	make lint
	make security
	make test

release-check:  ## Verifica se está pronto para release
	make clean
	make format-check
	make lint
	make security
	make test
	make build
	@echo "✅ Pronto para release!"

dev-setup:  ## Configuração inicial para desenvolvimento
	python -m venv venv
	@echo "Ative o ambiente virtual com:"
	@echo "  source venv/bin/activate  # Linux/Mac"
	@echo "  venv\\Scripts\\activate     # Windows"
	@echo "Depois execute: make install-dev"