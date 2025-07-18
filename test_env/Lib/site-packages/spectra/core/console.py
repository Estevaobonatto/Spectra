# -*- coding: utf-8 -*-
"""
Console management for Spectra
"""

import warnings
try:
    import requests
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
    from rich.syntax import Syntax
    from rich.panel import Panel
    from rich.text import Text
    
    # Suprime avisos para uma saída mais limpa
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    
except ImportError:
    print("[!] Erro: Bibliotecas Rich não encontradas.")
    print("[!] Por favor, instale-as com: pip install rich")
    import sys
    sys.exit(1)

# Console global para toda a aplicação
console = Console()

# Funções de utilidade para console
def print_success(message):
    """Imprime mensagem de sucesso."""
    console.print(f"[bold green][+][/bold green] {message}")

def print_error(message):
    """Imprime mensagem de erro."""
    console.print(f"[bold red][!][/bold red] {message}")

def print_warning(message):
    """Imprime mensagem de aviso."""
    console.print(f"[bold yellow][!][/bold yellow] {message}")

def print_info(message):
    """Imprime mensagem informativa."""
    console.print(f"[bold cyan][*][/bold cyan] {message}")

def print_separator(length=60):
    """Imprime separador."""
    console.print("-" * length)

def create_table(title, columns):
    """Cria uma tabela Rich."""
    table = Table(title=title)
    for column in columns:
        if isinstance(column, dict):
            table.add_column(**column)
        else:
            table.add_column(column)
    return table

def create_panel(content, title=None, style="cyan"):
    """Cria um painel Rich."""
    return Panel(content, title=title, style=style)

def create_progress():
    """Cria uma barra de progresso Rich."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console
    )
